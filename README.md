# SecureVault Commerce — Tienda Virtual con Autenticación Zero-Trust

Tienda virtual (catálogo, carrito, checkout) con un sistema de autenticación propio basado en principios **Zero-Trust**: en vez de confiar en la sesión una vez que el usuario inició sesión, cada login se evalúa con un motor de riesgo (reglas + Machine Learning) y, si el comportamiento es inusual, se exige una verificación adicional antes de dar acceso.

No usa Microsoft ni ningún servicio de Microsoft (sin Azure, sin Entra ID, sin MSAL). La autenticación es 100% propia.

---

## ¿Qué hace?

**Tienda**
- Catálogo con imágenes, descripción, precio y categoría por producto.
- Carrito de compras (agregar, cambiar cantidad, eliminar).
- Checkout con métodos de pago simulados (Yape, Visa, Mastercard).
- Historial de compras y perfil de usuario.
- Panel de administración: alta/baja de productos, auditoría, roles.

**Autenticación segura (el núcleo del proyecto)**
- Registro abierto a cualquier correo (Gmail, Hotmail, Outlook, institucional, etc.) — sin depender de un proveedor externo de identidad.
- Contraseñas nunca se guardan en texto plano (hash con Werkzeug).
- **Scoring de riesgo por login**: cada intento se analiza según hora, dispositivo, red, intentos fallidos recientes, usando un modelo híbrido de reglas + `IsolationForest` + `LocalOutlierFactor` (scikit-learn).
- **Verificación adicional (OTP)** cuando el riesgo es alto, antes de conceder la sesión.
- **Reautenticación continua**: si en medio de una sesión activa cambian la IP y el dispositivo a la vez, se vuelve a pedir verificación antes de dejar continuar en rutas sensibles (checkout, panel admin).
- Panel `/admin/anomalies` con el historial de intentos de login y su nivel de riesgo.
- Cabeceras de seguridad (CSP, HSTS, X-Frame-Options, etc.), CSRF, rate limiting.

---

## Stack

| Capa | Tecnología |
|---|---|
| Backend | Python 3 + Flask |
| Autenticación | Flask-Login + Werkzeug (hash de contraseñas) |
| Formularios / CSRF | Flask-WTF |
| Rate limiting | Flask-Limiter |
| Detección de anomalías | scikit-learn (IsolationForest, LocalOutlierFactor) |
| Base de datos | SQLite (desarrollo) |
| Frontend | Jinja2 + CSS propio (sin frameworks externos) |

Sin dependencias de Microsoft/Azure en ningún punto del stack.

---

## Estructura del proyecto

```
securevault-commerce/
├── app.py                    ← Rutas, modelos, configuración de la app
├── anomaly_detector.py       ← Motor de riesgo (reglas + ML)
├── requirements.txt
├── .env.example
├── instance/
│   ├── secureauth.db         ← Base de datos SQLite (se crea sola al arrancar, no se versiona)
│   └── uploads/               ← Imágenes subidas desde el panel admin
├── static/
│   ├── css/styles.css
│   └── img/
│       ├── placeholder.png
│       └── products/          ← Imágenes de catálogo (24 productos)
└── templates/
    ├── layout.html
    ├── index.html, product.html, cart.html, checkout.html
    ├── login.html, register.html, verify_otp.html
    ├── perfil.html, mis-compras.html
    └── admin.html, admin_product_new.html, admin_anomalies.html
```

---

## Instalación y uso local

```bash
# 1. Entrar a la carpeta del proyecto
cd securevault-commerce

# 2. Entorno virtual
python -m venv venv
source venv/bin/activate        # Mac/Linux
# venv\Scripts\activate         # Windows

# 3. Dependencias
pip install -r requirements.txt

# 4. Variables de entorno (opcional en local, recomendado en producción)
cp .env.example .env

# 5. Correr (crea la base de datos automáticamente la primera vez)
flask --app app run --debug
# → http://localhost:5000
```

### Usuarios de prueba (creados automáticamente al iniciar)

| Correo | Contraseña | Rol |
|---|---|---|
| carlos.mendoza.92@gmail.com | C4rl0s!2026Mx | admin |
| ana.rodriguez@hotmail.com | AnaSecure#2026 | user |
| miguel.torres@outlook.com | Miguel@Secure2026 | user |
| lucia.fernandez@gmail.com | LuciaSecure2026$ | user |
| jose.ramirez@yahoo.com | Jose#Secure2026! | user |

O regístrate con tu propio correo desde `/register`.

---

## Contexto académico

Este proyecto es la base aplicada del trabajo de investigación del curso DD281 Programación Segura (Universidad Autónoma del Perú), orientado a publicación Scopus Q1:

> **"Zero-Trust Behavioral Authentication: A Machine Learning-Enhanced Identity Verification Framework with Anomaly Detection for Continuous User Authentication in Cloud-Native Web Applications"**
> *(Autenticación de comportamiento de confianza cero: un marco de verificación de identidad mejorado con aprendizaje automático y detección de anomalías para la autenticación continua de usuarios en aplicaciones web nativas de la nube)*
> Target: Informática y Seguridad (Computers & Security) — Elsevier — Q1

La tienda virtual es el caso de uso donde se implementa y demuestra el motor de autenticación Zero-Trust descrito en el paper.
