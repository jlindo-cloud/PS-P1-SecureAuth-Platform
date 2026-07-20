# Política y arquitectura de seguridad

SecureAuth Store implementa defensa en profundidad organizada
en **cinco niveles**. Cada control es verificable en el código
y está cubierto por la suite de pruebas (`pytest -q`).

## Nivel 1 — Transporte (cifrado en tránsito)

- HTTPS forzado en producción (`FORCE_HTTPS`, redirección
  automática vía Flask-Talisman).
- HSTS con `max-age` de 1 año, `includeSubDomains` y `preload`
  (`app/__init__.py`).
- TLS 1.3 / mínimo 1.2 se configura en la capa de terminación
  TLS (Azure App Service: *Minimum TLS Version*; en Render el
  certificado y TLS 1.3 son automáticos). Gunicorn corre detrás
  del proxy con `ProxyFix` para respetar `X-Forwarded-Proto`.
- El canal del segundo factor también va cifrado. Dos vías,
  ambas con verificación de certificado
  (`ssl.create_default_context()`) y nunca en texto plano:
  - **API HTTPS** (Brevo o Resend) sobre el puerto 443. Es la
    vía necesaria en plataformas que bloquean los puertos SMTP
    salientes en sus planes gratuitos, como Render desde
    septiembre de 2025.
  - **SMTP con STARTTLS o SMTPS**, para desarrollo local y
    planes de pago.

## Nivel 2 — Almacenamiento (base de datos segura)

- Las contraseñas **nunca** se guardan en texto plano.
- Hash adaptativo **Argon2id** (`argon2-cffi`), con **salt único
  por usuario** embebido en cada hash.
- **Pepper** global del servidor (`PASSWORD_PEPPER`): la
  contraseña se procesa con `HMAC-SHA256(pepper, contraseña)`
  antes del hash. El pepper vive fuera de la base de datos
  (variable de entorno / Key Vault), de modo que una filtración
  de la BD no basta para atacar los hashes.
- Migración transparente: hashes creados antes del pepper se
  validan y se regeneran automáticamente en el primer login
  correcto (`app/auth.py: verify_password`).
- Re-hash automático si cambian los parámetros de Argon2
  (`check_needs_rehash`).

## Nivel 3 — Sesión (tokens y cookies)

- Cookie de sesión con `HttpOnly`, `Secure` (producción),
  `SameSite=Lax` y prefijo `__Host-` en producción
  (`app/config.py`).
- Rotación de sesión en cada login (`session.clear()` antes de
  emitir la nueva sesión) — mitiga fijación de sesión.
- Expiración corta configurable (`SESSION_MINUTES`, 30 por
  defecto) con refresco por request.
- No se usan JWT en el navegador; el estado viaja únicamente en
  la cookie firmada de Flask.

## Nivel 4 — Aplicación (lógica del login)

- **MFA por código OTP entregado por correo**: la contraseña
  correcta no concede la sesión; inicia un desafío de 6 dígitos
  con expiración de 5 minutos y máximo 5 intentos. En la sesión
  solo se guarda el HMAC del código, nunca el código en claro, y
  la comparación es de tiempo constante (`hmac.compare_digest`).
  El envío usa SMTP con STARTTLS (`app/mailer.py`); en producción
  la aplicación se niega a arrancar sin SMTP configurado, para
  que el segundo factor no quede inoperante.
- **Registro verificado**: el alta de cuenta también exige el
  código por correo, de modo que nadie puede registrarse con una
  dirección que no controla.
- **Política de contraseñas**: mínimo 12 caracteres con
  minúscula, mayúscula, número y símbolo (`RegisterForm`).
- **Interfaz sin fuga de datos**: en la pantalla de verificación
  el correo se muestra enmascarado (`p****l@gmail.com`).
- **Rate limiting** con Flask-Limiter: 5/min en login, 10/min en
  OTP, límites globales por IP.
- **Respuestas genéricas**: "Correo o contraseña incorrectos"
  sin distinguir el caso, y verificación contra un hash dummy
  cuando el usuario no existe, para igualar el tiempo de
  respuesta y evitar enumeración de usuarios. El registro
  responde igual exista o no la cuenta: si el correo ya está
  tomado, se avisa por correo al titular real en vez de
  revelarlo al visitante.
- Auditoría firmada (HMAC con `AUDIT_HMAC_KEY`) de cada evento:
  `LOGIN_PASSWORD_OK`, `LOGIN_SUCCESS`, `LOGIN_FAILED`,
  `MFA_FAILED`, `MFA_LOCKED`, `MFA_EXPIRED`.

## Disponibilidad y rate limiting

- Límites globales de 2000/día y 300/hora por dirección IP,
  más límites específicos por ruta sensible.
- **Archivos estáticos exentos**: una sola carga del catálogo
  son 12 imágenes más CSS y JS. Contarlas agotaba la cuota de
  un usuario legítimo en pocas visitas.
- **Sonda de salud `/health` exenta y sin acceso a la base**:
  el verificador de la plataforma consulta desde una IP fija
  cada pocos segundos; contra un endpoint limitado terminaba
  recibiendo 429, que se interpretaba como instancia caída y
  reiniciaba el servicio en bucle. Un control de seguridad mal
  ubicado se convierte en una negación de servicio contra uno
  mismo.
- `ProxyFix` respeta `X-Forwarded-For`, de modo que tras el
  proxy cada usuario mantiene su propia cuota en vez de
  compartir una sola.

## Nivel 5 — Infraestructura (servidor y cabeceras)

- **CSP** restrictiva, `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy`
  vía Flask-Talisman.
- **CSRF** en todos los formularios (Flask-WTF), verificado por
  `test_csrf_blocks_post_without_token`.
- Validación y saneamiento estricto de entradas: WTForms con
  longitudes máximas, rangos numéricos y expresiones regulares;
  consultas 100% parametrizadas con SQLAlchemy (sin
  concatenación de SQL); listas permitidas para ordenamientos.
- Carga de imágenes endurecida: límite de 2 MB, verificación del
  contenido real, rechazo de SVG, recodificación que elimina
  metadatos, nombre final UUID.

## Motor Zero-Trust de detección de anomalías

La autenticación no termina al validar la contraseña: cada
intento se evalúa contra el patrón de comportamiento habitual
de la cuenta (`app/anomaly_detector.py`).

**Características extraídas por intento**

| Característica | Qué mide |
|---|---|
| `hour_of_day` | Hora del acceso (0-23) |
| `day_of_week` | Día de la semana |
| `minutes_since_last_login` | Tiempo desde el último acceso correcto |
| `failed_attempts_recent` | Fallos en los últimos 15 minutos |
| `ip_changed` | La red no aparece en accesos previos |
| `user_agent_changed` | El dispositivo es nuevo |
| `new_device` | Red **y** dispositivo desconocidos |

**Enfoque híbrido**

1. **Reglas heurísticas**, siempre disponibles. Cubren el
   *cold start*: un usuario sin historial también recibe un
   veredicto.
2. **Modelos no supervisados** — `IsolationForest` y
   `LocalOutlierFactor` — que aprenden la distribución normal
   de accesos de cada cuenta y señalan las desviaciones. No
   requieren ejemplos etiquetados como ataque.

**El modelo solo puede elevar el riesgo, nunca reducirlo.**
Los modelos observan hora y día de la semana; sin ese piso,
una ráfaga de fallos desde un dispositivo desconocido (0.80
por reglas) quedaría diluida a riesgo medio solo porque el
horario es el habitual. Una señal dura de seguridad no puede
ser enmascarada por una estadística de comportamiento
(`test_el_ml_no_puede_enmascarar_una_regla_dura`).

**Qué hace el sistema con el veredicto**

El puntaje por reglas escala con la gravedad del patrón: una
ráfaga de 6 o más fallos suma 0.50, de modo que combinada con
un dispositivo desconocido supera el umbral de riesgo alto **a
cualquier hora**. Sin ese escalado el máximo diurno era 0.70
contra un umbral de 0.72, y el mismo ataque activaba el desafío
endurecido de madrugada pero no por la tarde
(`test_el_riesgo_no_depende_de_la_hora_del_reloj`).

| Riesgo | Efecto |
|---|---|
| Bajo | Segundo factor estándar: 5 minutos, 5 intentos |
| Medio | Igual, con el nivel registrado en la auditoría |
| Alto | Desafío endurecido: 2 minutos y 2 intentos |

> El OTP **se exige siempre**, cualquiera sea el riesgo. El
> motor endurece el segundo factor, no lo sustituye ni lo
> vuelve opcional: un análisis de comportamiento puede
> equivocarse, la posesión del correo no.

**Privacidad de los datos de comportamiento**

Las direcciones IP se almacenan **hasheadas** (SHA-256
truncado a 32 caracteres). El motor solo necesita saber si la
red es la misma de siempre, no cuál es. La tabla
`login_attempts` no contiene ningún dato personal en claro
más allá del correo.

**Resiliencia**

- Si `scikit-learn` no está instalado, el motor degrada a
  reglas en vez de fallar.
- Si el motor lanza una excepción, el login continúa con
  riesgo `unknown`: el componente de análisis nunca puede
  dejar a los usuarios fuera del sistema.

El panel `/admin/anomalies` (solo rol Admin) muestra el
historial con puntaje, nivel, método aplicado y factores
detectados.

## Seguridad del carrito y el pago

El proceso de compra aplica los mismos principios que la
autenticación: **nada de lo que envía el navegador se toma
como verdad**.

- **El total se recalcula en el servidor** a partir de los
  precios vigentes en la base de datos. Un total manipulado en
  el formulario se ignora (`test_total_se_calcula_en_el_servidor`).
- **Cantidades acotadas**: entre 1 y 20, y nunca por encima
  del stock disponible. Valores negativos devuelven 400.
- **Método y proveedor de pago validados contra listas
  permitidas**: `card` o `wallet`, y proveedor dentro del
  conjunto conocido. Texto arbitrario se rechaza.
- **No se almacenan datos sensibles de tarjeta.** Del pago solo
  persisten el método, el proveedor y los **últimos 4 dígitos**.
  El PAN completo, el CVV y la fecha de vencimiento nunca
  llegan a la base de datos
  (`test_no_se_almacenan_datos_sensibles_de_tarjeta`).
- **Sin autocompletado** en los campos de tarjeta
  (`autocomplete="off"`), para que el navegador no los conserve.
- **CSRF obligatorio** en agregar, actualizar y pagar.
- **Aislamiento entre usuarios (IDOR)**: cada consulta al
  carrito y a los pedidos filtra por el identificador del
  usuario en sesión. Un voucher ajeno devuelve 404, no 403,
  para no confirmar siquiera que el pedido existe.
- **Rate limiting** en checkout (10/min) y actualización de
  carrito (60/min).
- **Auditoría** de `CART_UPDATE` y de la creación del pedido.
- **Contador del carrito por sesión**: el número que aparece
  en la barra de navegación se calcula filtrando por el
  identificador del usuario en sesión, nunca por un parámetro
  del cliente (`test_contador_del_carrito_es_por_usuario`).
- **La interfaz no ofrece lo que el backend rechazaría**: sin
  sesión el catálogo muestra "Inicia sesión para comprar" en
  vez del botón de compra, y los productos sin stock no
  exponen el formulario. La restricción real sigue estando en
  el servidor: la interfaz solo evita el error innecesario.

> El checkout es un simulador académico: no procesa dinero real
> ni se conecta a una pasarela. Precisamente por eso los datos
> de tarjeta se descartan en vez de guardarse — en un sistema
> real esa información solo puede manejarla un proveedor
> certificado PCI DSS, nunca la aplicación.

## Reporte de vulnerabilidades

Si encuentras una vulnerabilidad, abre un *security advisory*
privado en GitHub o contacta al equipo del curso. No publiques
detalles en issues abiertos.
