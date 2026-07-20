# Configurar el envío del segundo factor

Guía para dejar funcionando la entrega del código OTP en el
despliegue de Render.

---

## Por qué SMTP no funciona en Render

Render **bloquea el tráfico saliente a los puertos SMTP 25, 465
y 587** en los servicios web del plan gratuito, medida aplicada
en todas las regiones desde el 26 de septiembre de 2025 para
evitar el abuso de spam.

Esto significa que Gmail por SMTP **no puede funcionar ahí**,
por más que las credenciales sean correctas. El síntoma es
exactamente el que se observó: funciona en local, y en
producción aparece *"No pudimos enviar el código de
verificación"*.

Las dos salidas son pagar un plan de Render, o usar un
proveedor de correo con **API HTTPS**, que viaja por el puerto
443 y no está afectado. El proyecto implementa la segunda.

> El cambio no debilita el Nivel 1 de seguridad: la API usa
> HTTPS con verificación de certificado
> (`ssl.create_default_context()`), igual que el STARTTLS que
> se usaba antes.

---

## Paso 1 — Crear la cuenta en Brevo

Se eligió Brevo porque su capa gratuita permite enviar a
**cualquier destinatario** (300 correos al día). La capa
gratuita de Resend, en cambio, solo envía a la dirección del
titular de la cuenta mientras no se verifique un dominio
propio, lo que impediría que otros usuarios se registren.

1. Entrar a [brevo.com](https://www.brevo.com) y crear una
   cuenta.
2. Confirmar el correo de registro.
3. Ir a **Senders, Domains & Dedicated IPs** → **Senders**.
4. Agregar el correo emisor (por ejemplo el mismo Gmail que se
   usaba como `SMTP_USER`) y verificarlo con el enlace que
   llega a esa casilla.

> El remitente **debe estar verificado** o la API rechaza el
> envío. Es el equivalente a la contraseña de aplicación de
> Gmail: prueba que controlas la dirección desde la que envías.

---

## Paso 2 — Generar la clave de API

1. En Brevo, menú superior derecho → **SMTP & API**.
2. Pestaña **API Keys** → **Generate a new API key**.
3. Nombre libre, por ejemplo `secureauth-render`.
4. Copiar el valor: empieza con `xkeysib-`.

> Solo se muestra una vez. Si se pierde, se genera otra y se
> revoca la anterior.

---

## Paso 3 — Configurar Render

En el panel del servicio → **Environment**:

| Variable | Valor |
|---|---|
| `BREVO_API_KEY` | la clave `xkeysib-...` |
| `MAIL_FROM` | `SecureAuth Store <correo-verificado@gmail.com>` |

El correo dentro de `MAIL_FROM` **debe ser el remitente
verificado en el paso 1**.

Las variables `SMTP_*` pueden quedarse: cuando hay API
configurada, tiene prioridad y SMTP no se usa. Sirven para
desarrollo local y para un eventual plan de pago.

**Save Changes** dispara el redespliegue automático.

---

## Paso 4 — Verificar

### Desde la aplicación

1. Abrir la URL pública y entrar a **Crear una cuenta**.
2. Registrarse con un correo real.
3. El código de 6 dígitos debe llegar en menos de un minuto.
4. Revisar **spam** la primera vez: un remitente nuevo suele
   caer ahí hasta que se marca como confiable.

### Desde la terminal

Con las mismas variables en el `.env` local:

```bash
python check_smtp.py tu-correo@gmail.com
```

El script detecta que hay API configurada, lo indica, y envía
un correo de prueba real.

### En los logs de Render

Buscar `mailer`. Si el envío falla, el traceback aparece ahí.

---

## Comportamiento según el entorno

| Situación | Dónde aparece el código |
|---|---|
| Local sin correo configurado | Consola de `run.py` |
| Local con API o SMTP | Bandeja de entrada |
| Local con correo fallando | Consola de `run.py` (respaldo) |
| Producción con correo funcionando | Bandeja de entrada |
| Producción con correo fallando | **En ningún lado**: se cancela el desafío y se muestra un aviso |

En producción no existe respaldo por consola a propósito: un
código de autenticación no debe escribirse en los logs de un
servidor. Por eso conviene verificar el correo **antes** de la
sustentación.

---

## Problemas frecuentes

| Síntoma | Causa | Solución |
|---|---|---|
| "No pudimos enviar el código" | Falta `BREVO_API_KEY` o el remitente no está verificado | Repasar pasos 1 a 3 |
| `TimeoutError` en los logs | Sigue usando SMTP: la clave de API no se cargó | Verificar el nombre exacto de la variable en Render |
| HTTP 401 desde la API | Clave inválida o revocada | Generar una nueva en Brevo |
| HTTP 400 desde la API | `MAIL_FROM` no coincide con el remitente verificado | Corregir `MAIL_FROM` |
| El correo llega a spam | Remitente nuevo sin reputación | Marcar como no spam; para producción real, verificar un dominio propio con SPF y DKIM |
| No llega a `@autonoma.edu.pe` | Filtro institucional estricto | Probar con Gmail para descartar |

---

## Nota sobre entornos reales

Para un sistema en producción real no bastaría con un
remitente verificado: haría falta un **dominio propio con
registros SPF y DKIM**, que es lo que permite a los servidores
receptores confirmar que el correo salió de quien dice. Sin
eso, la entrega depende de la reputación del proveedor y una
parte de los mensajes termina en spam.

Es una limitación aceptable para una demostración académica, y
conviene mencionarla como tal en vez de presentarla como
resuelta.
