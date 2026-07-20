"""
Envío de correo por SMTP con cifrado en tránsito.

Nivel 1 (transporte) aplicado también al canal del segundo
factor: la conexión al servidor SMTP usa STARTTLS o SMTPS,
nunca texto plano.

Si no hay servidor configurado, la aplicación degrada a modo
consola: registra el mensaje en el log en vez de enviarlo.
Esto permite desarrollar y ejecutar las pruebas sin
credenciales de correo, pero en producción es obligatorio
configurar SMTP (ver comprobación en app/__init__.py).
"""

import smtplib
import ssl
from email.message import EmailMessage

import requests
from flask import current_app


def mail_is_configured() -> bool:
    cfg = current_app.config

    if cfg.get("BREVO_API_KEY") or cfg.get("RESEND_API_KEY"):
        return bool(cfg.get("MAIL_FROM"))

    return bool(
        cfg.get("SMTP_HOST")
        and cfg.get("SMTP_USER")
        and cfg.get("SMTP_PASSWORD")
        and cfg.get("MAIL_FROM")
    )


def _split_from(value: str) -> tuple[str, str]:
    """Separa "Nombre <correo@dominio>" en sus dos partes."""
    if "<" in value and ">" in value:
        nombre, _, resto = value.partition("<")
        return nombre.strip(), resto.rstrip(">").strip()

    return "SecureAuth Store", value.strip()


# Destinos permitidos para el envío de correo.
#
# El endpoint nunca se construye con datos del usuario, pero se
# valida igualmente contra esta lista: un cliente HTTP que
# acepte cualquier URL es el punto de partida de un SSRF si en
# el futuro alguien hiciera configurable el destino.
# El destino se resuelve desde un identificador interno, nunca
# desde una URL recibida como argumento. Así no puede haber
# descoordinación entre quien llama y la lista permitida, y
# ninguna URL externa llega al cliente HTTP (OWASP A10 - SSRF).
_ENDPOINTS_PERMITIDOS = {
    "brevo": "https://api.brevo.com/v3/smtp/email",
    "resend": "https://api.resend.com/emails",
}


def _post_json(
    proveedor: str,
    payload: dict,
    headers: dict,
) -> bool:
    """
    POST con JSON sobre HTTPS al proveedor indicado.

    `proveedor` es una clave interna ("brevo" o "resend"), no
    una URL: el endpoint se busca en la tabla y un valor
    desconocido se rechaza antes de abrir ninguna conexión.

    Se usa `requests` en vez de `urllib.request.urlopen` porque
    este último acepta esquemas como `file://`, lo que
    convertiría cualquier URL no validada en una lectura de
    archivos locales (CWE-22). `requests` habla solo HTTP/HTTPS
    y verifica el certificado del servidor por omisión.
    """
    url = _ENDPOINTS_PERMITIDOS.get(proveedor)

    if url is None:
        raise ValueError(
            "Destino de correo no permitido."
        )

    respuesta = requests.post(
        url,
        json=payload,
        headers={
            "Content-Type": "application/json",
            **headers,
        },
        timeout=15,
        verify=True,
    )

    return respuesta.ok


def _send_via_http_api(
    to_address: str,
    subject: str,
    body: str,
) -> bool:
    """
    Envío por API HTTPS.

    Necesario en plataformas que bloquean los puertos SMTP
    salientes (25, 465, 587) en sus planes gratuitos, como
    Render. Al viajar sobre HTTPS (443) no se ve afectado por
    esa restricción, y mantiene el cifrado en tránsito del
    Nivel 1.
    """
    cfg = current_app.config
    nombre_remitente, correo_remitente = _split_from(
        cfg["MAIL_FROM"]
    )

    if cfg.get("BREVO_API_KEY"):
        return _post_json(
            "brevo",
            {
                "sender": {
                    "name": nombre_remitente,
                    "email": correo_remitente,
                },
                "to": [{"email": to_address}],
                "subject": subject,
                "textContent": body,
            },
            {"api-key": cfg["BREVO_API_KEY"]},
        )

    return _post_json(
        "resend",
        {
            "from": f"{nombre_remitente} <{correo_remitente}>",
            "to": [to_address],
            "subject": subject,
            "text": body,
        },
        {
            "Authorization": f"Bearer {cfg['RESEND_API_KEY']}",
        },
    )


def send_email(
    to_address: str,
    subject: str,
    body: str,
) -> bool:
    """
    Envía un correo de texto plano.

    Devuelve True si se entregó al servidor SMTP.
    Nunca propaga excepciones al flujo de autenticación:
    un fallo de correo no debe filtrar información ni
    romper la respuesta al usuario.
    """
    cfg = current_app.config

    if not mail_is_configured():
        current_app.logger.warning(
            "[SMTP NO CONFIGURADO] Para %s | %s\n%s",
            to_address,
            subject,
            body,
        )
        return False

    # Si hay API HTTPS configurada tiene prioridad sobre SMTP.
    if cfg.get("BREVO_API_KEY") or cfg.get("RESEND_API_KEY"):
        try:
            return _send_via_http_api(
                to_address,
                subject,
                body,
            )
        except Exception:
            current_app.logger.exception(
                "Fallo al enviar correo por API HTTPS."
            )

            if cfg["ENVIRONMENT"] != "production":
                current_app.logger.warning(
                    "[API FALLÓ — MODO DESARROLLO] Para %s | %s\n%s",
                    to_address,
                    subject,
                    body,
                )

            return False

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = cfg["MAIL_FROM"]
    message["To"] = to_address
    message.set_content(body)

    context = ssl.create_default_context()

    try:
        if cfg["SMTP_USE_SSL"]:
            with smtplib.SMTP_SSL(
                cfg["SMTP_HOST"],
                cfg["SMTP_PORT"],
                context=context,
                timeout=10,
            ) as server:
                server.login(
                    cfg["SMTP_USER"],
                    cfg["SMTP_PASSWORD"],
                )
                server.send_message(message)
        else:
            with smtplib.SMTP(
                cfg["SMTP_HOST"],
                cfg["SMTP_PORT"],
                timeout=10,
            ) as server:
                server.starttls(context=context)
                server.login(
                    cfg["SMTP_USER"],
                    cfg["SMTP_PASSWORD"],
                )
                server.send_message(message)

        return True

    except Exception:
        # Se registra sin incluir el cuerpo (contiene el código).
        current_app.logger.exception(
            "Fallo al enviar correo a un destinatario."
        )

        # En desarrollo, si el SMTP falla el usuario quedaría
        # sin forma de continuar. Se vuelca el mensaje al log
        # para no bloquear la demostración. En producción NO
        # se hace: el código nunca debe quedar en los logs de
        # un servidor accesible.
        if current_app.config["ENVIRONMENT"] != "production":
            current_app.logger.warning(
                "[SMTP FALLÓ — MODO DESARROLLO] Para %s | %s\n%s",
                to_address,
                subject,
                body,
            )

        return False
