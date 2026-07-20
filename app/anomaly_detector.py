"""
Zero-Trust Behavioral Authentication — Motor de detección de anomalías
=====================================================================

Capa de verificación continua de identidad, siguiendo el
principio Zero-Trust "never trust, always verify".

Enfoque híbrido:
  1. Reglas heurísticas de riesgo (siempre disponibles, cubren
     el "cold start" cuando un usuario todavía no tiene
     historial).
  2. Modelos no supervisados de Machine Learning —
     IsolationForest y Local Outlier Factor — que aprenden el
     patrón de comportamiento habitual de cada cuenta (hora del
     día, día de la semana, dispositivo, red) y detectan
     accesos que se desvían de ese patrón, una vez que existe
     suficiente historial.

Cada intento de login se transforma en un vector de
características:
  - hour_of_day               (0-23)
  - day_of_week               (0-6, 0 = lunes)
  - minutes_since_last_login  (minutos desde el último acceso)
  - failed_attempts_recent    (fallos en los últimos 15 min)
  - ip_changed                (1 si la red no aparece antes)
  - user_agent_changed        (1 si el dispositivo es nuevo)
  - new_device                (1 si red y dispositivo son nuevos)

`score_login()` devuelve:
  score          float 0..1  (0 = normal, 1 = altamente anómalo)
  risk_level     "low" | "medium" | "high"
  recommendation acción sugerida
  factors        motivos legibles por humanos
  method         "rules" | "isolation_forest+lof"

--------------------------------------------------------------
NOTA DE INTEGRACIÓN

Módulo original del planteamiento del grupo, adaptado para esta
entrega:

  - La lectura del historial pasó de SQL crudo sobre SQLite
    (`SELECT * FROM login_attempts`) a consultas SQLAlchemy
    sobre el modelo `LoginAttempt`. El SQL literal habría
    fallado en PostgreSQL al desplegar en producción.
  - Las direcciones IP se comparan **hasheadas**: el motor solo
    necesita saber si la red es la misma de siempre, no cuál es.
  - `scikit-learn` es opcional: sin él, el motor degrada a
    reglas heurísticas en vez de fallar.
--------------------------------------------------------------
"""

import hashlib
import math
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    from sklearn.neighbors import LocalOutlierFactor

    ML_AVAILABLE = True
except ImportError:  # pragma: no cover
    ML_AVAILABLE = False

# Numero minimo de intentos historicos para confiar en el modelo ML.
# Con menos muestras, IsolationForest/LOF no tienen suficiente contexto
# para diferenciar comportamiento normal de anomalo, asi que se usa el
# scoring basado en reglas (evita bloquear usuarios nuevos legitimos).
MIN_SAMPLES_FOR_ML = 8

RISK_THRESHOLDS = {"medium": 0.45, "high": 0.72}


def hash_ip(ip_address: str | None) -> str | None:
    """
    Huella estable de la dirección IP.

    Permite reconocer "la misma red de siempre" sin almacenar un
    dato personal identificable en la base.
    """
    if not ip_address:
        return None

    return hashlib.sha256(
        ip_address.encode("utf-8")
    ).hexdigest()[:32]


def _aware(value):
    """Normaliza a UTC: SQLite devuelve datetimes sin zona."""
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def _fetch_history(email, limit=200):
    """
    Historial de intentos del usuario, del más antiguo al más
    reciente. Consulta parametrizada por SQLAlchemy: el correo
    nunca se concatena en la sentencia SQL.
    """
    from .extensions import db
    from .models import LoginAttempt

    rows = db.session.execute(
        select(LoginAttempt)
        .where(LoginAttempt.email == email)
        .order_by(LoginAttempt.created_at.desc())
        .limit(limit)
    ).scalars().all()

    return list(reversed(rows))


def extract_features(email, ip_hash, user_agent, now=None):
    """Calcula el vector de caracteristicas de comportamiento para el
    intento de login actual, comparandolo contra el historial guardado
    en la tabla login_attempts."""
    now = now or datetime.now(timezone.utc)
    history = _fetch_history(email)
    successful = [h for h in history if h.success]

    last_login = _aware(successful[-1].created_at) if successful else None
    minutes_since_last = (
        min((now - last_login).total_seconds() / 60.0, 100000.0) if last_login else 100000.0
    )

    window_start = now - timedelta(minutes=15)
    failed_recent = sum(
        1
        for h in history
        if not h.success and (_aware(h.created_at) or now) >= window_start
    )

    known_ips = {h.ip_hash for h in successful if h.ip_hash}
    known_agents = {h.user_agent for h in successful if h.user_agent}

    ip_changed = 1 if successful and ip_hash not in known_ips else 0
    ua_changed = 1 if successful and user_agent not in known_agents else 0
    new_device = 1 if (ip_changed and ua_changed) else 0

    features = {
        "hour_of_day": now.hour,
        "day_of_week": now.weekday(),
        "minutes_since_last_login": minutes_since_last,
        "failed_attempts_recent": failed_recent,
        "ip_changed": ip_changed,
        "user_agent_changed": ua_changed,
        "new_device": new_device,
    }
    return features, history


def _rule_based_score(features):
    score = 0.0
    factors = []

    # Escalado por ráfaga de fallos.
    #
    # El tramo de 6 o más existe porque sin él el puntaje
    # máximo alcanzable en horario diurno era 0.70, por debajo
    # del umbral de riesgo alto (0.72): una fuerza bruta desde
    # un dispositivo desconocido a las 3 de la tarde nunca
    # activaba el desafío endurecido, y a las 3 de la mañana sí.
    # El nivel de riesgo no puede depender de la hora del reloj
    # cuando el patrón de ataque es inequívoco.
    if features["failed_attempts_recent"] >= 6:
        score += 0.50
        factors.append(
            f"{features['failed_attempts_recent']} intentos "
            "fallidos recientes (ráfaga)"
        )
    elif features["failed_attempts_recent"] >= 3:
        score += 0.35
        factors.append(f"{features['failed_attempts_recent']} intentos fallidos recientes")
    elif features["failed_attempts_recent"] >= 1:
        score += 0.15
        factors.append("Intentos fallidos recientes")

    if features["new_device"]:
        score += 0.30
        factors.append("Dispositivo y red no reconocidos")
    else:
        if features["ip_changed"]:
            score += 0.15
            factors.append("Direccion IP no reconocida")
        if features["user_agent_changed"]:
            score += 0.10
            factors.append("Navegador/dispositivo no reconocido")

    if features["hour_of_day"] < 5 or features["hour_of_day"] > 23:
        score += 0.15
        factors.append("Hora de acceso inusual (madrugada)")

    if features["minutes_since_last_login"] > 60 * 24 * 30:
        score += 0.05
        factors.append("Cuenta inactiva por tiempo prolongado")

    return min(score, 1.0), factors


def _ml_score(features, history):
    """Combina IsolationForest + Local Outlier Factor sobre el historial
    de vectores de comportamiento (hora del dia, dia de semana) del
    usuario. Ambos son modelos no supervisados: no requieren ejemplos
    previos etiquetados como "ataque", aprenden directamente la forma
    de la distribucion normal de accesos y senalan lo que se aleja de
    ella."""
    vectors = [
        [
            h.hour_of_day if h.hour_of_day is not None else 12,
            h.day_of_week if h.day_of_week is not None else 0,
        ]
        for h in history
    ]
    current_vector = [features["hour_of_day"], features["day_of_week"]]
    X = np.array(vectors + [current_vector], dtype=float)

    # --- IsolationForest ---
    iso = IsolationForest(n_estimators=100, contamination=0.15, random_state=42)
    iso.fit(X)
    iso_raw = iso.decision_function(X)[-1]  # mayor = mas normal
    iso_score = 1 / (1 + math.exp(iso_raw * 6))  # sigmoide -> 0..1, mayor = mas anomalo

    # --- Local Outlier Factor ---
    lof_score = 0.5
    if len(X) >= MIN_SAMPLES_FOR_ML:
        n_neighbors = min(20, len(X) - 1)
        lof = LocalOutlierFactor(n_neighbors=n_neighbors)
        lof.fit_predict(X)
        neg_outlier = lof.negative_outlier_factor_[-1]
        lof_score = 1 / (1 + math.exp((neg_outlier + 1.5) * 3))

    combined = (iso_score * 0.6) + (lof_score * 0.4)
    return min(max(combined, 0.0), 1.0)


def score_login(email, ip_hash, user_agent, now=None):
    """Punto de entrada principal: calcula el riesgo de un intento de
    login y devuelve una recomendacion de accion (permitir, monitorear
    o exigir verificacion adicional)."""
    features, history = extract_features(email, ip_hash, user_agent, now)
    rule_score, factors = _rule_based_score(features)

    method = "rules"
    score = rule_score

    if ML_AVAILABLE and len(history) >= MIN_SAMPLES_FOR_ML:
        try:
            ml_score = _ml_score(features, history)
            combinado = (ml_score * 0.65) + (rule_score * 0.35)

            # El modelo puede ELEVAR el riesgo, nunca reducirlo
            # por debajo de lo que dictan las reglas.
            #
            # Los modelos no supervisados solo observan hora y
            # día de la semana. Sin este piso, una ráfaga de
            # fallos desde un dispositivo desconocido (0.80 por
            # reglas) quedaría diluida a riesgo medio solo
            # porque el horario es el habitual. Una señal dura
            # de seguridad no puede ser enmascarada por una
            # estadística de comportamiento.
            score = min(1.0, max(combinado, rule_score))

            method = "isolation_forest+lof"
            if ml_score > 0.6:
                factors.append(
                    "Patrón de comportamiento fuera de lo "
                    "habitual (modelo ML)"
                )
        except Exception:
            method = "rules"
            score = rule_score

    if score >= RISK_THRESHOLDS["high"]:
        risk_level = "high"
        recommendation = "Requiere verificacion adicional (codigo de un solo uso) antes de conceder la sesion."
    elif score >= RISK_THRESHOLDS["medium"]:
        risk_level = "medium"
        recommendation = "Sesion concedida con monitoreo reforzado en acciones sensibles."
    else:
        risk_level = "low"
        recommendation = "Comportamiento consistente con el historial del usuario."

    if not factors:
        factors.append("Sin factores de riesgo detectados")

    return {
        "score": round(score, 3),
        "risk_level": risk_level,
        "recommendation": recommendation,
        "factors": factors,
        "method": method,
        "features": features,
    }
