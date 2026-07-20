"""
Pruebas del motor Zero-Trust de detección de anomalías.

Verifican que cada intento se registre, que el riesgo escale
ante comportamiento anómalo, que el segundo factor se endurezca
en consecuencia y que el panel esté restringido a Admin.
"""

from datetime import datetime, timedelta, timezone

import pytest

from app.anomaly_detector import hash_ip, score_login
from app.extensions import db
from app.models import LoginAttempt, User


PASSWORD = "Correcta#2026!"
IP_HABITUAL = "198.51.100.10"
IP_NUEVA = "203.0.113.99"
UA_HABITUAL = "Mozilla/5.0 (Windows NT 10.0) Navegador/1.0"
UA_NUEVO = "Desconocido/9.9"


@pytest.fixture()
def usuario(app):
    from app.auth import hash_password

    user = User(
        email="analisis@example.com",
        name="Usuario Análisis",
        password_hash=hash_password(PASSWORD),
        role="Customer",
        active=True,
    )
    db.session.add(user)
    db.session.commit()
    return user


def _registrar(email, success, ip, ua, minutos_atras=0, hora=14):
    momento = datetime.now(timezone.utc) - timedelta(
        minutes=minutos_atras
    )
    db.session.add(
        LoginAttempt(
            email=email,
            success=success,
            ip_hash=hash_ip(ip),
            user_agent=ua,
            hour_of_day=hora,
            day_of_week=momento.weekday(),
            created_at=momento,
        )
    )
    db.session.commit()


# ---------------------------------------------------------
# La IP nunca se guarda en claro
# ---------------------------------------------------------

def test_la_ip_se_almacena_hasheada(app):
    huella = hash_ip(IP_HABITUAL)

    assert huella is not None
    assert IP_HABITUAL not in huella
    assert len(huella) == 32
    # Determinista: la misma IP produce la misma huella.
    assert huella == hash_ip(IP_HABITUAL)
    assert huella != hash_ip(IP_NUEVA)


def test_ip_ausente_no_rompe_el_motor(app):
    assert hash_ip(None) is None
    assert hash_ip("") is None


# ---------------------------------------------------------
# Puntuación de riesgo
# ---------------------------------------------------------

def test_cold_start_usa_reglas(app, usuario):
    """Sin historial el motor no puede aplicar ML, pero debe
    devolver un veredicto igualmente."""
    riesgo = score_login(
        usuario.email,
        hash_ip(IP_HABITUAL),
        UA_HABITUAL,
    )

    assert riesgo["method"] == "rules"
    assert riesgo["risk_level"] in ("low", "medium", "high")
    assert 0.0 <= riesgo["score"] <= 1.0


def test_dispositivo_y_red_nuevos_elevan_el_riesgo(
    app, usuario
):
    for i in range(5):
        _registrar(
            usuario.email, True, IP_HABITUAL, UA_HABITUAL,
            minutos_atras=60 * (i + 1),
        )

    habitual = score_login(
        usuario.email, hash_ip(IP_HABITUAL), UA_HABITUAL,
    )
    sospechoso = score_login(
        usuario.email, hash_ip(IP_NUEVA), UA_NUEVO,
    )

    assert sospechoso["score"] > habitual["score"]
    assert any(
        "no reconocid" in f.lower()
        for f in sospechoso["factors"]
    )


def test_fallos_recientes_elevan_el_riesgo(app, usuario):
    base = score_login(
        usuario.email, hash_ip(IP_HABITUAL), UA_HABITUAL,
    )["score"]

    for _ in range(4):
        _registrar(
            usuario.email, False, IP_HABITUAL, UA_HABITUAL,
            minutos_atras=2,
        )

    tras_fallos = score_login(
        usuario.email, hash_ip(IP_HABITUAL), UA_HABITUAL,
    )

    assert tras_fallos["score"] > base
    assert any(
        "fallidos" in f.lower()
        for f in tras_fallos["factors"]
    )


def test_el_motor_no_lanza_sin_scikit_learn(
    app, usuario, monkeypatch
):
    """Sin la librería de ML el motor degrada a reglas en vez
    de fallar: la autenticación nunca debe caerse por el
    componente de análisis."""
    import app.anomaly_detector as motor

    monkeypatch.setattr(motor, "ML_AVAILABLE", False)

    for i in range(30):
        _registrar(
            usuario.email, True, IP_HABITUAL, UA_HABITUAL,
            minutos_atras=60 * (i + 1),
        )

    riesgo = motor.score_login(
        usuario.email, hash_ip(IP_HABITUAL), UA_HABITUAL,
    )

    assert riesgo["method"] == "rules"
    assert riesgo["risk_level"] in ("low", "medium", "high")


# ---------------------------------------------------------
# Integración con el login
# ---------------------------------------------------------

def test_cada_intento_queda_registrado(client, usuario):
    client.post(
        "/auth/login",
        data={"email": usuario.email, "password": "Incorrecta#1"},
    )
    client.post(
        "/auth/login",
        data={"email": usuario.email, "password": PASSWORD},
    )

    intentos = (
        db.session.query(LoginAttempt)
        .filter_by(email=usuario.email)
        .order_by(LoginAttempt.id)
        .all()
    )

    assert len(intentos) == 2
    assert intentos[0].success is False
    assert intentos[1].success is True
    # El veredicto del motor quedó guardado con el intento.
    assert intentos[1].risk_level is not None
    assert intentos[1].risk_method is not None


def test_riesgo_alto_endurece_el_segundo_factor(
    client, usuario, app
):
    """Ante comportamiento anómalo el código OTP vive menos y
    admite menos intentos, pero se sigue exigiendo siempre."""
    # Historial habitual: red y dispositivo conocidos.
    for i in range(5):
        _registrar(
            usuario.email, True, IP_HABITUAL, UA_HABITUAL,
            minutos_atras=60 * (i + 1),
        )

    # Ráfaga de fallos desde una red y un equipo desconocidos.
    for _ in range(6):
        _registrar(
            usuario.email, False, IP_NUEVA, UA_NUEVO,
            minutos_atras=1,
        )

    response = client.post(
        "/auth/login",
        data={"email": usuario.email, "password": PASSWORD},
        environ_base={"REMOTE_ADDR": IP_NUEVA},
        headers={"User-Agent": UA_NUEVO},
    )

    assert response.status_code == 302
    assert "/auth/otp" in response.headers["Location"]

    with client.session_transaction() as sess:
        desafio = sess["pending_mfa"]
        assert desafio["risk_level"] == "high"
        assert (
            desafio["attempts_left"]
            < app.config["OTP_MAX_ATTEMPTS"]
        )
        assert (
            desafio["ttl_minutes"]
            < app.config["OTP_TTL_SECONDS"] // 60
        )


def test_el_otp_se_exige_incluso_con_riesgo_bajo(
    client, usuario
):
    """El segundo factor no es condicional: un riesgo bajo no
    concede la sesión directamente."""
    response = client.post(
        "/auth/login",
        data={"email": usuario.email, "password": PASSWORD},
    )

    assert "/auth/otp" in response.headers["Location"]
    with client.session_transaction() as sess:
        assert "user" not in sess


# ---------------------------------------------------------
# Panel de anomalías
# ---------------------------------------------------------

def test_panel_de_anomalias_requiere_admin(app):
    """Clientes independientes: las fixtures de sesión comparten
    el mismo cliente y se pisarían entre sí."""
    anonimo = app.test_client()
    assert anonimo.get("/admin/anomalies").status_code == 302

    cliente = app.test_client()
    with cliente.session_transaction() as sess:
        sess["user"] = {
            "oid": "customer-1", "name": "Cliente",
            "username": "cliente@example.com",
            "roles": ["Customer"],
        }
    assert cliente.get("/admin/anomalies").status_code == 403

    admin = app.test_client()
    with admin.session_transaction() as sess:
        sess["user"] = {
            "oid": "admin-1", "name": "Admin",
            "username": "admin@example.com",
            "roles": ["Admin"],
        }
    assert admin.get("/admin/anomalies").status_code == 200


def test_el_ml_no_puede_enmascarar_una_regla_dura(
    app, usuario
):
    """El modelo estadístico solo observa hora y día. No debe
    poder rebajar el riesgo cuando las reglas ya detectaron
    una señal fuerte (ráfaga de fallos + dispositivo nuevo)."""
    from app.anomaly_detector import (
        RISK_THRESHOLDS,
        _rule_based_score,
        extract_features,
    )

    # Historial amplio y homogéneo: alimenta al modelo.
    for i in range(30):
        _registrar(
            usuario.email, True, IP_HABITUAL, UA_HABITUAL,
            minutos_atras=60 * (i + 1),
        )

    for _ in range(6):
        _registrar(
            usuario.email, False, IP_NUEVA, UA_NUEVO,
            minutos_atras=1,
        )

    features, _ = extract_features(
        usuario.email, hash_ip(IP_NUEVA), UA_NUEVO,
    )
    puntaje_reglas, _ = _rule_based_score(features)

    riesgo = score_login(
        usuario.email, hash_ip(IP_NUEVA), UA_NUEVO,
    )

    # El veredicto no depende de la hora del reloj: la ráfaga
    # de fallos más el dispositivo desconocido bastan.
    assert puntaje_reglas >= RISK_THRESHOLDS["high"]
    # Aunque el modelo intervenga, el veredicto no baja.
    assert riesgo["score"] >= puntaje_reglas
    assert riesgo["risk_level"] == "high"


def test_el_riesgo_no_depende_de_la_hora_del_reloj(app, usuario):
    """Una ráfaga de fallos desde un dispositivo desconocido es
    riesgo alto a cualquier hora.

    Antes del escalado por ráfaga, el puntaje máximo diurno era
    0.70 contra un umbral de 0.72: el mismo ataque activaba el
    desafío endurecido de madrugada y no lo activaba por la
    tarde.
    """
    from app.anomaly_detector import RISK_THRESHOLDS, _rule_based_score

    for hora in (3, 14, 21):
        features = {
            "hour_of_day": hora,
            "day_of_week": 2,
            "minutes_since_last_login": 60.0,
            "failed_attempts_recent": 6,
            "ip_changed": 1,
            "user_agent_changed": 1,
            "new_device": 1,
        }

        puntaje, _ = _rule_based_score(features)

        assert puntaje >= RISK_THRESHOLDS["high"], (
            f"a las {hora}h el puntaje fue {puntaje}"
        )
