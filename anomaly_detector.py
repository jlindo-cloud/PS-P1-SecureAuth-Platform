"""
Zero-Trust Behavioral Authentication - ML Anomaly Detection Module
====================================================================

Implementa la capa de verificacion continua de identidad para
SecureVault Commerce, siguiendo el principio Zero-Trust
"never trust, always verify".

Enfoque hibrido:
  1. Reglas heuristicas de riesgo (siempre disponibles, cubren el
     "cold start" cuando un usuario todavia no tiene historial).
  2. Modelos no supervisados de Machine Learning -- IsolationForest y
     Local Outlier Factor (LOF) -- que aprenden el patron de
     comportamiento habitual de cada cuenta (hora del dia, dia de la
     semana, dispositivo, red) y detectan accesos que se desvian de
     ese patron, una vez que existe suficiente historial.

Cada intento de login se transforma en un vector de caracteristicas:
  - hour_of_day               (0-23)
  - day_of_week                (0-6, 0 = lunes)
  - minutes_since_last_login   (minutos desde el ultimo login exitoso)
  - failed_attempts_recent     (intentos fallidos en los ultimos 15 min)
  - ip_changed                 (1 si la IP no aparece en logins previos)
  - user_agent_changed         (1 si el navegador/dispositivo es nuevo)
  - new_device                 (1 si IP y User-Agent son ambos nuevos)

`score_login()` devuelve un diccionario con:
  score          float 0..1  (0 = normal, 1 = altamente anomalo)
  risk_level     "low" | "medium" | "high"
  recommendation texto explicando la accion sugerida
  factors        lista de motivos legibles por humanos
  method         "rules" | "isolation_forest+lof"
"""

import math
from datetime import datetime, timedelta

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    from sklearn.neighbors import LocalOutlierFactor
    ML_AVAILABLE = True
except ImportError:  # pragma: no cover - entorno sin scikit-learn instalado
    ML_AVAILABLE = False

# Numero minimo de intentos historicos para confiar en el modelo ML.
# Con menos muestras, IsolationForest/LOF no tienen suficiente contexto
# para diferenciar comportamiento normal de anomalo, asi que se usa el
# scoring basado en reglas (evita bloquear usuarios nuevos legitimos).
MIN_SAMPLES_FOR_ML = 8

RISK_THRESHOLDS = {"medium": 0.45, "high": 0.72}


def _parse_dt(value):
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None


def _fetch_history(conn, email, limit=200):
    rows = conn.execute(
        "SELECT * FROM login_attempts WHERE email = ? ORDER BY created_at DESC LIMIT ?",
        (email, limit),
    ).fetchall()
    return list(reversed(rows))


def extract_features(conn, email, ip_address, user_agent, now=None):
    """Calcula el vector de caracteristicas de comportamiento para el
    intento de login actual, comparandolo contra el historial guardado
    en la tabla login_attempts."""
    now = now or datetime.now()
    history = _fetch_history(conn, email)
    successful = [h for h in history if h["success"]]

    last_login = _parse_dt(successful[-1]["created_at"]) if successful else None
    minutes_since_last = (
        min((now - last_login).total_seconds() / 60.0, 100000.0) if last_login else 100000.0
    )

    window_start = now - timedelta(minutes=15)
    failed_recent = sum(
        1
        for h in history
        if not h["success"] and (_parse_dt(h["created_at"]) or now) >= window_start
    )

    known_ips = {h["ip_address"] for h in successful if h["ip_address"]}
    known_agents = {h["user_agent"] for h in successful if h["user_agent"]}

    ip_changed = 1 if successful and ip_address not in known_ips else 0
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

    if features["failed_attempts_recent"] >= 3:
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
            h["hour_of_day"] if h["hour_of_day"] is not None else 12,
            h["day_of_week"] if h["day_of_week"] is not None else 0,
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


def score_login(conn, email, ip_address, user_agent, now=None):
    """Punto de entrada principal: calcula el riesgo de un intento de
    login y devuelve una recomendacion de accion (permitir, monitorear
    o exigir verificacion adicional)."""
    features, history = extract_features(conn, email, ip_address, user_agent, now)
    rule_score, factors = _rule_based_score(features)

    method = "rules"
    score = rule_score

    if ML_AVAILABLE and len(history) >= MIN_SAMPLES_FOR_ML:
        try:
            ml_score = _ml_score(features, history)
            score = min(1.0, (ml_score * 0.65) + (rule_score * 0.35))
            method = "isolation_forest+lof"
            if ml_score > 0.6:
                factors.append("Patron de comportamiento fuera de lo habitual (modelo ML)")
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
