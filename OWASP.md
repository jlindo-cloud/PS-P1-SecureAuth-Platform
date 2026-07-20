# Cobertura del OWASP Top 10 (2021)

Mapeo de cada categoría del OWASP Top 10 a los controles
implementados en SecureAuth Store, con el archivo donde vive
cada control y la prueba automatizada que lo verifica.

Ejecutar la evidencia completa:

```bash
pytest -q     # 46 pruebas
```

---

## A01:2021 — Pérdida de control de acceso

| Control | Dónde |
|---|---|
| RBAC por decorador en las 7 rutas administrativas | `app/security.py: role_required` |
| El rol se lee de la sesión del servidor, nunca del cliente | `app/security.py: current_user` |
| Consultas de carrito y pedidos filtradas por el usuario en sesión | `app/store.py` |
| Voucher ajeno devuelve **404**, no 403: no confirma que el recurso exista | `app/store.py` |
| Redirecciones validadas contra *open redirect* | `app/security.py: is_safe_relative_url` |

**Pruebas:** `test_admin_requires_authentication`,
`test_customer_cannot_access_admin`, `test_cart_idor_is_blocked`,
`test_voucher_ajeno_no_es_accesible`,
`test_panel_de_anomalias_requiere_admin`

---

## A02:2021 — Fallos criptográficos

| Control | Dónde |
|---|---|
| **Argon2id** con salt único por usuario | `app/auth.py: hash_password` |
| **Pepper** global fuera de la base de datos (HMAC-SHA256 previo al hash) | `app/auth.py: _pepper_password` |
| Re-hash automático si cambian los parámetros de Argon2 | `check_needs_rehash` |
| HTTPS forzado y HSTS de 1 año con preload | `app/__init__.py` (Talisman) |
| SMTP con STARTTLS y verificación de certificado | `app/mailer.py` |
| Direcciones IP almacenadas hasheadas, nunca en claro | `app/anomaly_detector.py: hash_ip` |
| Del pago solo persisten los últimos 4 dígitos: nunca PAN ni CVV | `app/store.py` |

**Pruebas:** `test_hash_no_verifica_sin_pepper`,
`test_verify_password_con_pepper`,
`test_hash_legado_migra_a_pepper`,
`test_no_se_almacenan_datos_sensibles_de_tarjeta`,
`test_la_ip_se_almacena_hasheada`

---

## A03:2021 — Inyección

| Control | Dónde |
|---|---|
| Consultas 100% parametrizadas con SQLAlchemy; sin concatenación | todo el proyecto |
| Ordenamiento por **lista permitida**, no por texto del usuario | `app/store.py: sort_map` |
| Método y proveedor de pago validados contra listas permitidas | `app/store.py` |
| Sin credenciales escritas en el código: el token de billetera se lee de la configuración y se compara en tiempo constante | `app/config.py: WALLET_DEMO_TOKEN` |
| Autoescape de Jinja2 activo; sin `\|safe` ni `Markup` en ninguna plantilla | `app/templates/` |
| Validación estricta con WTForms: longitudes, rangos y expresiones regulares | `app/forms.py` |

**Pruebas:** `test_sql_injection_payload_is_data_not_code`,
`test_metodo_de_pago_desconocido_es_rechazado`,
`test_proveedor_fuera_de_la_lista_permitida`,
`test_metodo_y_proveedor_deben_ser_coherentes`

---

## A04:2021 — Diseño inseguro

| Control | Dónde |
|---|---|
| **MFA obligatorio**: la contraseña por sí sola nunca concede sesión | `app/auth.py` |
| **Motor Zero-Trust**: cada intento se puntúa contra el patrón habitual de la cuenta | `app/anomaly_detector.py` |
| El modelo de ML solo puede **elevar** el riesgo, nunca enmascarar una regla dura | `app/anomaly_detector.py: score_login` |
| El total del pedido se recalcula en el servidor: un total manipulado se ignora | `app/store.py` |
| Cantidades acotadas al stock; valores negativos rechazados | `app/store.py` |
| Degradación segura: si el motor de riesgo falla, el login continúa; si falla el correo en producción, el acceso se **deniega** | `app/auth.py` |

**Pruebas:** `test_password_correcta_no_da_sesion_directa`,
`test_el_otp_se_exige_incluso_con_riesgo_bajo`,
`test_el_ml_no_puede_enmascarar_una_regla_dura`,
`test_total_se_calcula_en_el_servidor`,
`test_cantidad_no_puede_superar_el_stock`

---

## A05:2021 — Configuración de seguridad incorrecta

| Control | Dónde |
|---|---|
| Cabeceras CSP, `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy` | `app/__init__.py` (Talisman) |
| `script-src 'self'`: sin JavaScript embebido en las plantillas | `app/static/js/` |
| `DEBUG` imposible de activar en producción | `app/config.py` |
| La aplicación **se niega a arrancar** en producción sin `FLASK_SECRET_KEY`, `PASSWORD_PEPPER` o SMTP | `app/__init__.py` |
| Cookies con `HttpOnly`, `Secure`, `SameSite=Lax` y prefijo `__Host-` | `app/config.py` |
| `.env` excluido del repositorio; secretos por variables de entorno | `.gitignore`, `render.yaml` |

**Pruebas:** `test_security_headers`

---

## A06:2021 — Componentes vulnerables y desactualizados

| Control | Dónde |
|---|---|
| `pip-audit` sobre `requirements.txt` en cada push y cada lunes | `.github/workflows/security-checks.yml` |
| `bandit` (SAST) sobre el paquete `app`: **0 hallazgos** en todas las severidades | mismo workflow |
| Dependencias con rangos de versión acotados (`>=x,<y`) | `requirements.txt` |
| `scikit-learn` opcional: su ausencia degrada a reglas, no rompe la autenticación | `app/anomaly_detector.py` |

**Prueba:** `test_el_motor_no_lanza_sin_scikit_learn`

---

## A07:2021 — Fallos de identificación y autenticación

| Control | Dónde |
|---|---|
| Segundo factor por código de un solo uso enviado al correo | `app/auth.py: verify_otp` |
| En sesión solo se guarda el **HMAC** del código, comparado en tiempo constante | `app/auth.py: _otp_digest` |
| Expiración de 5 minutos y máximo 5 intentos; **2 y 2 ante riesgo alto** | `app/auth.py: start_otp_challenge` |
| Rate limiting: 5/min en login, 10/min en OTP, 5/hora en registro | Flask-Limiter |
| **Anti-enumeración**: mensaje idéntico exista o no la cuenta, y verificación contra un hash *dummy* para igualar el tiempo de respuesta | `app/auth.py` |
| Registro verificado por correo: nadie se registra con una dirección ajena | `app/auth.py: register` |
| Política de contraseñas: 12+ caracteres con cuatro clases | `app/forms.py: RegisterForm` |
| Rotación de sesión en cada login (anti fijación) | `session.clear()` |

**Pruebas:** `test_otp_correcto_concede_sesion`,
`test_otp_incorrecto_es_rechazado`,
`test_otp_se_bloquea_tras_agotar_intentos`,
`test_registro_exige_password_fuerte`,
`test_registro_duplicado_no_revela_existencia`,
`test_riesgo_alto_endurece_el_segundo_factor`

---

## A08:2021 — Fallos de integridad del software y los datos

| Control | Dónde |
|---|---|
| Registro de auditoría **firmado con HMAC** (`AUDIT_HMAC_KEY`): una fila alterada deja de validar | `app/audit.py` |
| CSRF obligatorio en todos los formularios | Flask-WTF |
| Imágenes **recodificadas** al subirlas: se eliminan metadatos y contenido embebido; SVG rechazado | `app/storage.py` |
| Nombre de archivo generado por UUID, nunca el que envía el cliente | `app/storage.py` |
| Migraciones versionadas con Alembic: el esquema no se altera a mano | `migrations/` |

**Pruebas:** `test_csrf_blocks_post_without_token`,
`test_svg_is_rejected`,
`test_token_de_billetera_no_esta_en_el_codigo`

---

## A09:2021 — Fallos de registro y monitoreo

| Control | Dónde |
|---|---|
| Auditoría de eventos de seguridad: `LOGIN_SUCCESS`, `LOGIN_FAILED`, `MFA_FAILED`, `MFA_LOCKED`, `MFA_EXPIRED`, `MFA_DELIVERY_FAILED`, `USER_REGISTERED`, `CART_UPDATE` | `app/audit.py` |
| Historial de intentos con puntaje de riesgo y factores detectados | `app/models.py: LoginAttempt` |
| Panel `/admin/auditoria` con los últimos 200 eventos | `app/admin.py` |
| Panel `/admin/anomalies` con el resumen de riesgo por nivel | `app/admin.py` |
| Los logs **no contienen** códigos OTP en producción ni contraseñas | `app/mailer.py` |

**Prueba:** `test_cada_intento_queda_registrado`

> **Limitación reconocida:** no hay alertado automático ante
> una ráfaga de riesgo alto. El monitoreo es por consulta del
> administrador. Un sistema en producción real debería enviar
> notificación al detectar `MFA_LOCKED` repetido o varios
> intentos `high` sobre la misma cuenta.

---

## A10:2021 — Falsificación de solicitudes del lado del servidor (SSRF)

La aplicación **no realiza peticiones HTTP salientes a URLs
controladas por el usuario**, que es el vector propio de esta
categoría. No hay funciones de "importar imagen desde URL",
webhooks configurables ni proxies.

Las conexiones salientes son a destinos fijos definidos en
variables de entorno del servidor:

| Destino | Control |
|---|---|
| Servidor SMTP | Host de configuración, no de entrada del usuario |
| Proveedor OIDC de Google | URL fija de metadatos |
| Azure Blob Storage | URL de cuenta desde configuración |

Además, el parámetro `next` del login está restringido a rutas
relativas del propio sitio (`is_safe_relative_url`), lo que
cierra el *open redirect* que suele acompañar a esta clase de
ataques.

---

## Resumen

| Categoría | Estado |
|---|---|
| A01 Control de acceso | Cubierto |
| A02 Fallos criptográficos | Cubierto |
| A03 Inyección | Cubierto |
| A04 Diseño inseguro | Cubierto |
| A05 Configuración incorrecta | Cubierto |
| A06 Componentes vulnerables | Cubierto (CI) |
| A07 Autenticación | Cubierto |
| A08 Integridad | Cubierto |
| A09 Registro y monitoreo | Cubierto, sin alertado automático |
| A10 SSRF | No aplica por diseño |
