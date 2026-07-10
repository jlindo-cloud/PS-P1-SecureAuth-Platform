import os
import secrets
import sqlite3
import uuid
from datetime import timedelta, datetime

from flask import (
    Flask, render_template, redirect, url_for, request, flash, session,
    abort, jsonify, send_from_directory,
)
from flask_wtf import FlaskForm, CSRFProtect
from flask_wtf.csrf import CSRFError
from wtforms import StringField, PasswordField, SubmitField, IntegerField, FileField, HiddenField, SelectField
from wtforms.validators import DataRequired, Length, Email, NumberRange, EqualTo, ValidationError
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

import anomaly_detector

app = Flask(__name__, instance_relative_config=True)
IS_PRODUCTION = os.environ.get("FLASK_ENV") == "production"
app.config.from_mapping(
    SECRET_KEY=os.environ.get("FLASK_SECRET_KEY", "change_me_secret"),
    SESSION_COOKIE_SECURE=IS_PRODUCTION,
    REMEMBER_COOKIE_SECURE=IS_PRODUCTION,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    MAX_CONTENT_LENGTH=4 * 1024 * 1024,
    WTF_CSRF_ENABLED=IS_PRODUCTION,
)

csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

limiter = Limiter(app=app, key_func=get_remote_address, default_limits=["20 per minute"])

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}
UPLOAD_FOLDER = os.path.join(app.instance_path, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
PRODUCT_IMG_FOLDER = os.path.join(app.root_path, "static", "img", "products")

DATABASE = os.path.join(app.instance_path, "secureauth.db")

# Endpoints considerados sensibles para la verificacion continua Zero-Trust:
# si durante una sesion activa cambian simultaneamente la IP y el dispositivo
# justo antes de acceder a uno de ellos, se exige reverificacion (step-up).
SENSITIVE_ENDPOINTS = {
    "checkout", "admin_panel", "admin_product_new",
    "admin_change_role", "admin_product_delete", "admin_anomalies",
}


def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


class User(UserMixin):
    def __init__(self, id_, email, role="user"):
        self.id = id_
        self.email = email
        self.role = role

    def get_id(self):
        return str(self.id)

    def is_admin(self):
        return self.role == "admin"


@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    if user:
        return User(user["id"], user["email"], user["role"])
    return None


def validate_password_strength(form, field):
    pwd = field.data or ""
    if len(pwd) < 10:
        raise ValidationError("La contraseña debe tener al menos 10 caracteres.")
    if not any(c.isupper() for c in pwd):
        raise ValidationError("Debe incluir al menos una letra mayúscula.")
    if not any(c.islower() for c in pwd):
        raise ValidationError("Debe incluir al menos una letra minúscula.")
    if not any(c.isdigit() for c in pwd):
        raise ValidationError("Debe incluir al menos un número.")
    if not any(c in "!@#$%^&*()-_=+[]{};:,.<>?/|~" for c in pwd):
        raise ValidationError("Debe incluir al menos un carácter especial.")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8, max=128)])
    submit = SubmitField("Iniciar sesión")


class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField("Contraseña", validators=[DataRequired(), validate_password_strength])
    confirm_password = PasswordField(
        "Confirmar contraseña",
        validators=[DataRequired(), EqualTo("password", message="Las contraseñas no coinciden.")],
    )
    submit = SubmitField("Crear cuenta")


class OTPForm(FlaskForm):
    code = StringField("Código de verificación", validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField("Verificar")


class ProductForm(FlaskForm):
    name = StringField("Nombre", validators=[DataRequired(), Length(max=120)])
    description = StringField("Descripción", validators=[DataRequired(), Length(max=500)])
    price = IntegerField("Precio", validators=[DataRequired(), NumberRange(min=0)])
    category = SelectField(
        "Categoría",
        choices=[("Electrónica", "Electrónica"), ("Ropa", "Ropa"), ("Hogar", "Hogar"),
                 ("Deportes", "Deportes"), ("Libros", "Libros"), ("Otros", "Otros")],
        validators=[DataRequired()],
    )
    image = FileField("Imagen")
    submit = SubmitField("Guardar")


class CartItemForm(FlaskForm):
    product_id = HiddenField("product_id", validators=[DataRequired()])
    quantity = IntegerField("Cantidad", validators=[DataRequired(), NumberRange(min=1, max=20)])
    submit = SubmitField("Agregar al carrito")


class CheckoutForm(FlaskForm):
    payment_method = SelectField("Método de pago", choices=[("yape", "Yape"), ("visa", "Visa"), ("mastercard", "Mastercard")], validators=[DataRequired()])
    phone = StringField("Celular", validators=[Length(max=15)])
    card_holder = StringField("Titular", validators=[Length(max=100)])
    card_number = StringField("Número", validators=[Length(max=19)])
    card_expiry = StringField("Vencimiento", validators=[Length(max=5)])
    card_cvv = StringField("CVV", validators=[Length(max=4)])
    submit = SubmitField("Finalizar compra")


@app.before_request
def enforce_https_and_security_headers():
    host = request.host.split(':')[0].lower()
    is_localhost = host in ("127.0.0.1", "localhost", "0.0.0.0", "::1")

    if request.is_secure is False and IS_PRODUCTION and not is_localhost:
        return redirect(request.url.replace("http://", "https://"), code=301)

    if is_localhost:
        # Allow local HTTP debugging even when FLASK_ENV=production.
        # This ensures cookies will still be sent for localhost-based sessions.
        app.config["SESSION_COOKIE_SECURE"] = False
        app.config["REMEMBER_COOKIE_SECURE"] = False

    return None


@app.before_request
def continuous_zero_trust_check():
    """Verificacion continua de identidad (Zero-Trust): en rutas sensibles,
    si la IP y el dispositivo del usuario cambian simultaneamente respecto
    a los usados al iniciar sesion, se exige reverificacion antes de
    continuar, en lugar de confiar ciegamente en la cookie de sesion."""
    if not current_user.is_authenticated:
        return None
    if request.endpoint not in SENSITIVE_ENDPOINTS:
        return None
    if session.get("step_up_required"):
        return redirect(url_for("verify_otp"))

    login_ip = session.get("login_ip")
    login_ua = session.get("login_ua")
    current_ip = request.remote_addr
    current_ua = request.headers.get("User-Agent", "")[:255]

    if login_ip and login_ua and current_ip != login_ip and current_ua != login_ua:
        _issue_otp(current_user.email)
        session["step_up_required"] = True
        session["step_up_reason"] = "Detectamos un cambio simultáneo de red y dispositivo durante tu sesión activa."
        session["step_up_next"] = request.path
        log_audit(actor=current_user.email, action="continuous_auth_challenge",
                  metadata=f"ip {login_ip}->{current_ip}", ip=current_ip)
        flash("Por seguridad (Zero-Trust), verifica tu identidad nuevamente antes de continuar.", "warning")
        return redirect(url_for("verify_otp"))
    return None


@app.after_request
def set_security_headers(response):
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' https: data:; connect-src 'self'"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    return response


# ---------------------------------------------------------------------------
# Autenticación Zero-Trust: helpers de OTP y registro de intentos de login
# ---------------------------------------------------------------------------

def send_otp_email(email, code):
    print(f"[EMAIL] To: {email}, Subject: Código de verificación SecureVault")
    print(f"[EMAIL] Tu código de verificación Zero-Trust es: {code} (vence en 5 minutos)")


def _issue_otp(email):
    code = f"{secrets.randbelow(1000000):06d}"
    session["otp_code"] = code
    session["otp_expires"] = (datetime.now() + timedelta(minutes=5)).isoformat()
    session["otp_attempts"] = 0
    send_otp_email(email, code)
    # En entorno de desarrollo mostramos el código para poder probar el flujo
    # sin un servidor de correo real configurado.
    if not app.debug and os.environ.get("FLASK_ENV") == "production":
        return code
    flash(f"[MODO DESARROLLO] Código de verificación: {code}", "warning")
    return code


def _clear_step_up_session():
    for key in ("pending_user_id", "pending_email", "otp_code", "otp_expires", "otp_attempts",
                "step_up_required", "step_up_reason", "step_up_next"):
        session.pop(key, None)


def _record_login_attempt(conn, email, success, ip_address, user_agent,
                           risk_score=None, risk_level=None, factors=None):
    now = datetime.now()
    conn.execute(
        """INSERT INTO login_attempts
           (email, success, ip_address, user_agent, hour_of_day, day_of_week,
            risk_score, risk_level, factors, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            email, 1 if success else 0, ip_address, user_agent,
            now.hour, now.weekday(),
            risk_score, risk_level, "; ".join(factors) if factors else None,
            now.isoformat(),
        ),
    )
    conn.commit()


def log_audit(actor, action, metadata="", ip=None):
    conn = get_db_connection()
    conn.execute(
        "INSERT INTO audit_logs (actor, action, metadata, ip_address, created_at) VALUES (?, ?, ?, ?, ?)",
        (actor, action, metadata, ip or request.remote_addr, datetime.now().isoformat())
    )
    conn.commit()
    conn.close()


def send_admin_email(subject, html_content):
    admin_email = "carlos.mendoza.92@gmail.com"
    print(f"[EMAIL] To: {admin_email}, Subject: {subject}")
    print(f"[EMAIL] Content: {html_content[:200]}...")


# ---------------------------------------------------------------------------
# Rutas principales
# ---------------------------------------------------------------------------

@app.route("/")
@limiter.limit("20 per minute")
def index():
    conn = get_db_connection()
    products = conn.execute("SELECT * FROM products").fetchall()
    conn.close()
    return render_template("index.html", products=products)


@app.route("/media/<path:filename>")
def media(filename):
    """Sirve imágenes de producto tanto de las subidas por el admin
    (instance/uploads) como de las incluidas con el proyecto
    (static/img/products), evitando el hack anterior de apuntar el
    endpoint 'static' fuera de su carpeta (que no funcionaba)."""
    safe_name = secure_filename(filename)
    if not safe_name:
        abort(404)
    uploads_path = os.path.join(app.config["UPLOAD_FOLDER"], safe_name)
    if os.path.isfile(uploads_path):
        return send_from_directory(app.config["UPLOAD_FOLDER"], safe_name)
    if os.path.isfile(os.path.join(PRODUCT_IMG_FOLDER, safe_name)):
        return send_from_directory(PRODUCT_IMG_FOLDER, safe_name)
    abort(404)


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        ip_address = request.remote_addr
        user_agent = request.headers.get("User-Agent", "")[:255]

        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        password_ok = bool(user) and check_password_hash(user["password"], form.password.data)

        if not form.email.data or not form.password.data:
            conn.close()
            flash("Completa ambos campos para continuar.", "warning")
            return render_template("login.html", form=form)

        if not password_ok:
            _record_login_attempt(conn, email, success=False, ip_address=ip_address, user_agent=user_agent)
            conn.close()
            log_audit(actor=email, action="login_failed", metadata="Credenciales inválidas", ip=ip_address)
            flash("Credenciales inválidas.", "danger")
            return render_template("login.html", form=form)

        risk = anomaly_detector.score_login(conn, email, ip_address, user_agent)
        _record_login_attempt(
            conn, email, success=True, ip_address=ip_address, user_agent=user_agent,
            risk_score=risk["score"], risk_level=risk["risk_level"], factors=risk["factors"],
        )
        conn.close()

        log_audit(
            actor=email, action="login_success",
            metadata=f"risk={risk['risk_level']} score={risk['score']} method={risk['method']}",
            ip=ip_address,
        )

        if risk["risk_level"] == "high":
            session["pending_user_id"] = user["id"]
            session["pending_email"] = email
            session["step_up_reason"] = "Detectamos actividad inusual en este inicio de sesión: " + "; ".join(risk["factors"])
            session["step_up_next"] = url_for("index")
            _issue_otp(email)
            flash("Zero-Trust: nunca confiar, siempre verificar. Te enviamos un código de verificación adicional.", "warning")
            return redirect(url_for("verify_otp"))

        user_obj = User(user["id"], user["email"], user["role"])
        login_user(user_obj)
        session["login_ip"] = ip_address
        session["login_ua"] = user_agent

        if risk["risk_level"] == "medium":
            flash("Sesión iniciada. Se solicitará verificación adicional si detectamos más cambios en tu acceso.", "warning")

        return redirect(url_for("index"))
    return render_template("login.html", form=form)


@app.route("/register", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        conn = get_db_connection()
        existing = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
        if existing:
            conn.close()
            flash("Ya existe una cuenta registrada con ese correo.", "danger")
            return render_template("register.html", form=form)

        password_hash = generate_password_hash(form.password.data)
        conn.execute(
            "INSERT INTO users (email, password, role) VALUES (?, ?, ?)",
            (email, password_hash, "user"),
        )
        conn.commit()
        conn.close()
        log_audit(actor=email, action="user_registered", metadata="Registro con correo propio", ip=request.remote_addr)
        flash("Cuenta creada correctamente. Ya puedes iniciar sesión.", "success")
        return redirect(url_for("login"))
    return render_template("register.html", form=form)


@app.route("/verify-otp", methods=["GET", "POST"])
@limiter.limit("15 per minute")
def verify_otp():
    pending_login = "pending_user_id" in session
    step_up = bool(session.get("step_up_required")) and current_user.is_authenticated

    if not pending_login and not step_up:
        flash("No hay ninguna verificación pendiente.", "warning")
        return redirect(url_for("login"))

    form = OTPForm()
    reason = session.get("step_up_reason", "Verificación de seguridad requerida.")

    if form.validate_on_submit():
        code = form.code.data.strip()
        if len(code) != 6 or not code.isdigit():
            flash("El código debe contener 6 dígitos.", "danger")
            return render_template("verify_otp.html", form=form, reason=reason)
        expires = session.get("otp_expires")
        expired = True
        if expires:
            try:
                expired = datetime.now() > datetime.fromisoformat(expires)
            except ValueError:
                expired = True

        if expired:
            flash("El código expiró. Vuelve a iniciar sesión.", "danger")
            _clear_step_up_session()
            if current_user.is_authenticated:
                logout_user()
            return redirect(url_for("login"))

        if code != session.get("otp_code"):
            attempts = session.get("otp_attempts", 0) + 1
            session["otp_attempts"] = attempts
            if attempts >= 5:
                flash("Demasiados intentos incorrectos. Vuelve a iniciar sesión.", "danger")
                _clear_step_up_session()
                if current_user.is_authenticated:
                    logout_user()
                return redirect(url_for("login"))
            flash("Código incorrecto. Inténtalo nuevamente.", "danger")
            return render_template("verify_otp.html", form=form, reason=reason)

        ip_address = request.remote_addr
        user_agent = request.headers.get("User-Agent", "")[:255]

        if pending_login:
            user_id = session["pending_user_id"]
            conn = get_db_connection()
            user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
            conn.close()
            if not user:
                _clear_step_up_session()
                flash("Usuario no encontrado.", "danger")
                return redirect(url_for("login"))
            user_obj = User(user["id"], user["email"], user["role"])
            login_user(user_obj)
            log_audit(actor=user["email"], action="otp_verified_login", ip=ip_address)
        else:
            log_audit(actor=current_user.email, action="otp_verified_reauth", ip=ip_address)

        next_url = session.get("step_up_next") or url_for("index")
        session["login_ip"] = ip_address
        session["login_ua"] = user_agent
        _clear_step_up_session()
        flash("Identidad verificada correctamente.", "success")
        return redirect(next_url)

    return render_template("verify_otp.html", form=form, reason=reason)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for("index"))


@app.route("/product/<int:product_id>")
@limiter.limit("20 per minute")
def product_detail(product_id):
    conn = get_db_connection()
    product = conn.execute("SELECT * FROM products WHERE id = ?", (product_id,)).fetchone()
    conn.close()
    if not product:
        abort(404)
    cart_form = CartItemForm(product_id=product_id, quantity=1)
    return render_template("product.html", product=product, cart_form=cart_form)


@app.route("/cart", methods=["GET", "POST"])
@limiter.limit("20 per minute")
def cart():
    cart = session.get("cart", {})
    conn = get_db_connection()
    product_ids = tuple(cart.keys())
    products = []
    if product_ids:
        query = f"SELECT * FROM products WHERE id IN ({','.join('?' for _ in product_ids)})"
        products = conn.execute(query, tuple(product_ids)).fetchall()
    conn.close()
    cart_items = []
    total = 0
    for product in products:
        quantity = cart.get(str(product["id"]), 0)
        subtotal = product["price"] * quantity
        total += subtotal
        cart_items.append({"product": product, "quantity": quantity, "subtotal": subtotal})
    return render_template("cart.html", cart_items=cart_items, total=total)


@app.route("/cart/add", methods=["POST"])
@limiter.limit("30 per minute")
def add_to_cart():
    form = CartItemForm()
    if form.validate_on_submit():
        conn = get_db_connection()
        product = conn.execute("SELECT id FROM products WHERE id = ?", (form.product_id.data,)).fetchone()
        conn.close()
        if not product:
            flash("Producto no encontrado.", "danger")
            return redirect(url_for("index"))
        cart = session.setdefault("cart", {})
        product_id = str(form.product_id.data)
        cart[product_id] = min(cart.get(product_id, 0) + form.quantity.data, 20)
        session["cart"] = cart
        flash("Producto agregado al carrito.", "success")
    else:
        flash("No se pudo añadir el producto.", "danger")
    return redirect(request.referrer or url_for("index"))


@app.route("/cart/update/<int:product_id>", methods=["POST"])
@limiter.limit("30 per minute")
def update_cart(product_id):
    cart = session.get("cart", {})
    pid = str(product_id)
    quantity = request.form.get("quantity", type=int)
    if quantity is None or quantity < 1:
        if pid in cart:
            del cart[pid]
            session["cart"] = cart
        return redirect(url_for("cart"))
    quantity = min(quantity, 20)
    cart[pid] = quantity
    session["cart"] = cart
    return redirect(url_for("cart"))


@app.route("/cart/remove/<int:product_id>", methods=["POST"])
@limiter.limit("30 per minute")
def remove_from_cart(product_id):
    cart = session.get("cart", {})
    pid = str(product_id)
    if pid in cart:
        del cart[pid]
        session["cart"] = cart
        flash("Producto eliminado del carrito.", "success")
    return redirect(url_for("cart"))


@app.route("/admin")
@login_required
@limiter.limit("10 per minute")
def admin_panel():
    if not current_user.is_admin():
        abort(403)
    conn = get_db_connection()
    users = conn.execute("SELECT id, email, role FROM users").fetchall()
    products = conn.execute("SELECT * FROM products").fetchall()
    audit_logs = conn.execute("SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 25").fetchall()
    total_audit = conn.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0]
    conn.close()
    in_stock = sum(1 for p in products if (p["stock"] or 0) > 0)
    return render_template(
        "admin.html", users=users, products=products,
        audit_logs=audit_logs, total_audit=total_audit, in_stock=in_stock,
    )


@app.route("/admin/anomalies")
@login_required
@limiter.limit("10 per minute")
def admin_anomalies():
    if not current_user.is_admin():
        abort(403)
    conn = get_db_connection()
    attempts = conn.execute(
        "SELECT * FROM login_attempts ORDER BY created_at DESC LIMIT 100"
    ).fetchall()
    conn.close()
    high_risk = [a for a in attempts if a["risk_level"] == "high"]
    medium_risk = [a for a in attempts if a["risk_level"] == "medium"]
    failed = [a for a in attempts if not a["success"]]
    return render_template(
        "admin_anomalies.html", attempts=attempts,
        high_risk=high_risk, medium_risk=medium_risk, failed=failed,
    )


@app.route("/admin/product/new", methods=["GET", "POST"])
@login_required
@limiter.limit("10 per minute")
def admin_product_new():
    if not current_user.is_admin():
        abort(403)
    form = ProductForm()
    if form.validate_on_submit():
        image_filename = None
        image = form.image.data
        if image:
            filename = secure_filename(image.filename)
            extension = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
            if extension not in ALLOWED_EXTENSIONS:
                flash("Tipo de archivo no permitido.", "danger")
                return redirect(request.url)
            filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            image.save(filepath)
            image_filename = filename
        conn = get_db_connection()
        conn.execute(
            "INSERT INTO products (name, description, price, image_url, category, stock) VALUES (?, ?, ?, ?, ?, ?)",
            (form.name.data, form.description.data, form.price.data, image_filename, form.category.data, 10),
        )
        conn.commit()
        conn.close()
        log_audit(actor=current_user.email, action="product_created", metadata=f"Producto: {form.name.data}", ip=request.remote_addr)
        flash("Producto creado correctamente.", "success")
        return redirect(url_for("admin_panel"))
    return render_template("admin_product_new.html", form=form)


@app.route("/admin/product/<int:product_id>/delete", methods=["POST"])
@login_required
@limiter.limit("10 per minute")
def admin_product_delete(product_id):
    if not current_user.is_admin():
        abort(403)
    conn = get_db_connection()
    product = conn.execute("SELECT * FROM products WHERE id = ?", (product_id,)).fetchone()
    if not product:
        conn.close()
        abort(404)
    conn.execute("DELETE FROM products WHERE id = ?", (product_id,))
    conn.commit()
    conn.close()
    log_audit(actor=current_user.email, action="product_deleted", metadata=f"Producto: {product['name']}", ip=request.remote_addr)
    flash("Producto eliminado.", "success")
    return redirect(url_for("admin_panel"))


@app.route("/admin/user/<int:user_id>/role", methods=["POST"])
@login_required
@limiter.limit("10 per minute")
def admin_change_role(user_id):
    if not current_user.is_admin():
        abort(403)
    if user_id == int(current_user.id):
        flash("No puedes cambiar tu propio rol desde aquí.", "warning")
        return redirect(url_for("admin_panel"))
    new_role = request.form.get("role")
    if new_role not in ("user", "admin"):
        abort(400)
    conn = get_db_connection()
    conn.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
    conn.commit()
    conn.close()
    log_audit(actor=current_user.email, action="role_changed", metadata=f"user_id={user_id} -> {new_role}", ip=request.remote_addr)
    flash("Rol de usuario actualizado.", "success")
    return redirect(url_for("admin_panel"))


@app.route("/checkout", methods=["GET", "POST"])
@login_required
@limiter.limit("20 per minute")
def checkout():
    form = CheckoutForm()
    cart = session.get("cart", {})
    conn = get_db_connection()
    product_ids = tuple(cart.keys())
    products = []
    if product_ids:
        query = f"SELECT * FROM products WHERE id IN ({','.join('?' for _ in product_ids)})"
        products = conn.execute(query, tuple(product_ids)).fetchall()
    conn.close()

    cart_items = []
    total = 0
    for product in products:
        quantity = cart.get(str(product["id"]), 0)
        subtotal = product["price"] * quantity
        total += subtotal
        cart_items.append({"product": product, "quantity": quantity, "subtotal": subtotal})

    if not cart_items:
        return render_template("checkout.html", cart_items=[], total=0, form=form, show_success=False)

    if form.validate_on_submit():
        order_number = f"ORD-{uuid.uuid4().hex[:8].upper()}"
        payment_detail = ""
        if form.payment_method.data == "yape":
            payment_detail = f"Celular: {form.phone.data}"
        elif form.payment_method.data in ("visa", "mastercard"):
            payment_detail = f"Tarjeta: ****-****-****-{form.card_number.data[-4:] if form.card_number.data else '****'}"

        conn = get_db_connection()
        conn.execute(
            "INSERT INTO purchases (order_number, user_id, total, payment_method, payment_detail, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (order_number, current_user.id, total, form.payment_method.data, payment_detail, "completed", datetime.now().isoformat())
        )
        purchase_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

        for item in cart_items:
            conn.execute(
                "INSERT INTO purchase_items (purchase_id, product_id, quantity, price) VALUES (?, ?, ?, ?)",
                (purchase_id, item["product"]["id"], item["quantity"], item["product"]["price"])
            )
        conn.commit()
        conn.close()

        log_audit(
            actor=current_user.email,
            action="purchase_completed",
            metadata=f"Order: {order_number}, Total: {total}, Method: {form.payment_method.data}"
        )

        email_html = f"""
        <h2>Nueva compra completada</h2>
        <p><strong>Orden:</strong> {order_number}</p>
        <p><strong>Cliente:</strong> {current_user.email}</p>
        <p><strong>Total:</strong> ${total:.2f}</p>
        <p><strong>Método:</strong> {form.payment_method.data.title()}</p>
        """
        send_admin_email("Nueva compra - SECUREVAULT", email_html)

        session.pop("cart", None)
        return render_template("checkout.html",
            cart_items=cart_items,
            total=total,
            order_number=order_number,
            payment_method=form.payment_method.data,
            show_success=True,
            created_at=datetime.now().strftime("%d/%m/%Y %H:%M"))

    return render_template("checkout.html", cart_items=cart_items, total=total, form=form, show_success=False)


@app.route("/perfil")
@login_required
@limiter.limit("20 per minute")
def perfil():
    conn = get_db_connection()
    purchases = conn.execute(
        "SELECT * FROM purchases WHERE user_id = ? ORDER BY created_at DESC",
        (current_user.id,)
    ).fetchall()

    total_purchases = len(purchases)
    total_spent = sum(p["total"] for p in purchases)
    pending_count = sum(1 for p in purchases if p["status"] != "completed")

    yape_count = sum(1 for p in purchases if p["payment_method"] == "yape")
    yape_total = sum(p["total"] for p in purchases if p["payment_method"] == "yape")
    visa_count = sum(1 for p in purchases if p["payment_method"] == "visa")
    visa_total = sum(p["total"] for p in purchases if p["payment_method"] == "visa")
    mc_count = sum(1 for p in purchases if p["payment_method"] == "mastercard")
    mc_total = sum(p["total"] for p in purchases if p["payment_method"] == "mastercard")
    conn.close()

    return render_template("perfil.html",
        total_purchases=total_purchases,
        total_spent=total_spent,
        pending_count=pending_count,
        yape_count=yape_count, yape_total=yape_total,
        visa_count=visa_count, visa_total=visa_total,
        mc_count=mc_count, mc_total=mc_total,
        purchases=purchases)


@app.route("/mis-compras")
@login_required
@limiter.limit("20 per minute")
def mis_compras():
    conn = get_db_connection()
    purchases = conn.execute(
        "SELECT * FROM purchases WHERE user_id = ? ORDER BY created_at DESC",
        (current_user.id,)
    ).fetchall()
    conn.close()

    return render_template("mis-compras.html", purchases=purchases)


@app.errorhandler(403)
def forbidden(error):
    return render_template("403.html"), 403


@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    flash("Error de seguridad: el formulario no fue enviado correctamente. Recarga la página e intenta de nuevo.", "danger")
    form = LoginForm()
    return render_template("login.html", form=form), 400


@app.errorhandler(404)
def page_not_found(error):
    return render_template("404.html"), 404


@app.cli.command("init-db")
def init_db_command():
    """Comando de consola para inicializar la base de datos de forma manual."""
    init_db()
    print("Base de datos inicializada de forma manual.")


def init_db():
    """Crea las tablas e inyecta usuarios/productos de prueba si no existen."""
    os.makedirs(app.instance_path, exist_ok=True)

    conn = get_db_connection()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user'
    );
    CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT NOT NULL,
        price INTEGER NOT NULL,
        image_url TEXT,
        category TEXT DEFAULT 'Otros',
        stock INTEGER DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS purchases (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_number TEXT UNIQUE NOT NULL,
        user_id INTEGER NOT NULL,
        total INTEGER NOT NULL,
        payment_method TEXT NOT NULL,
        payment_detail TEXT,
        status TEXT NOT NULL DEFAULT 'completed',
        created_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users (id)
    );
    CREATE TABLE IF NOT EXISTS purchase_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        purchase_id INTEGER NOT NULL,
        product_id INTEGER NOT NULL,
        quantity INTEGER NOT NULL,
        price INTEGER NOT NULL,
        FOREIGN KEY (purchase_id) REFERENCES purchases (id)
    );
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        actor TEXT NOT NULL,
        action TEXT NOT NULL,
        metadata TEXT,
        ip_address TEXT,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS login_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL,
        success INTEGER NOT NULL,
        ip_address TEXT,
        user_agent TEXT,
        hour_of_day INTEGER,
        day_of_week INTEGER,
        risk_score REAL,
        risk_level TEXT,
        factors TEXT,
        created_at TEXT NOT NULL
    );
    """)

    cursor = conn.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        # Cuentas de prueba con distintos proveedores de correo (gmail,
        # hotmail, outlook, yahoo) para demostrar que el registro/login ya
        # no está restringido a un único dominio corporativo.
        test_users = [
            ("carlos.mendoza.92@gmail.com", "C4rl0s!2026Mx", "admin"),
            ("ana.rodriguez@hotmail.com", "AnaSecure#2026", "user"),
            ("miguel.torres@outlook.com", "Miguel@Secure2026", "user"),
            ("lucia.fernandez@gmail.com", "LuciaSecure2026$", "user"),
            ("jose.ramirez@yahoo.com", "Jose#Secure2026!", "user"),
        ]
        for email, pwd, role in test_users:
            conn.execute(
                "INSERT INTO users (email, password, role) VALUES (?, ?, ?)",
                (email, generate_password_hash(pwd), role),
            )
        print("Usuarios de prueba inyectados correctamente (contraseñas hasheadas).")

    cursor = conn.execute("SELECT COUNT(*) FROM products")
    if cursor.fetchone()[0] == 0:
        conn.executemany("""
            INSERT INTO products (name, description, price, image_url, category, stock)
            VALUES (?, ?, ?, ?, ?, ?)
        """, [
            ("Token de Autenticación FIDO2", "Llave física criptográfica para MFA resistente al phishing.", 850, "token.jpg", "Electrónica", 25),
            ("Software Antimalware Enterprise", "Licencia anual para protección de endpoints con IA.", 1200, "antivirus.jpg", "Electrónica", 50),
            ("Router SecureEdge", "Router empresarial con firewall avanzado y actualizaciones seguras.", 460, "router.jpg", "Electrónica", 20),
            ("Cámara IP SafeCam", "Cámara con cifrado extremo a extremo y alertas inteligentes.", 310, "camaras.jpg", "Electrónica", 35),
            ("Camiseta SecurityOps", "Camiseta premium con diseño de código binario y logo de seguridad.", 45, "camiseta.jpg", "Ropa", 100),
            ("Hoodie ZeroTrust", "Sudadera térmica con diseño minimalista y parche RBAC.", 90, "hoodie.jpg", "Ropa", 60),
            ("Gorra Authenticator", "Gorra ligera con bordado de clave de autenticación.", 28, "gorra.jpg", "Ropa", 120),
            ("Polo ThreatIntel", "Polo con tecnología de tejido antiestática.", 55, "polo.jpg", "Ropa", 80),
            ("Lámpara ZeroTrust", "Lámpara inteligente con autenticación biométrica.", 250, "lampara.jpg", "Hogar", 15),
            ("Cerradura SmartSafe", "Cerradura inteligente con registro de accesos y cifrado.", 190, "cerradura.jpg", "Hogar", 25),
            ("Sensor de Movimiento Guard", "Sensor con detección avanzada y alertas en tiempo real.", 65, "sensor.jpg", "Hogar", 90),
            ("Alarma SecureHome", "Sistema de alarma para hogar con panel cifrado.", 420, "alarma.jpg", "Hogar", 10),
            ("Zapatillas EncryptRun", "Zapatillas para running con suela antibloqueo y conectividad.", 180, "zapatillas.jpg", "Deportes", 30),
            ("Mochila VaultPack", "Mochila resistente al agua con compartimento seguro.", 120, "mochila.jpg", "Deportes", 22),
            ("Botella HidrateShield", "Botella térmica con tapa a prueba de fugas.", 35, "botella.jpg", "Deportes", 150),
            ("Guantes ActiveSecure", "Guantes con agarre antideslizante para entrenamientos.", 40, "guantes.jpg", "Deportes", 80),
            ("Libro Ciberseguridad Avanzada", "Guía completa de seguridad empresarial moderna.", 75, "libro.jpg", "Libros", 200),
            ("Manual de Criptografía Práctica", "Introducción y ejercicios para criptografía aplicada.", 110, "criptografia.jpg", "Libros", 140),
            ("Guía de DevSecOps", "Patrones y prácticas para integrar seguridad en CI/CD.", 98, "devsecops.jpg", "Libros", 160),
            ("Libro OSINT en Acción", "Casos y metodología para análisis OSINT.", 85, "osint.jpg", "Libros", 180),
            ("Tarjeta Regalo SecureVault", "Tarjeta regalo para comprar productos en SecureVault Commerce.", 60, "giftcard.jpg", "Otros", 300),
            ("Kit de Inicio Passwords", "Kit educativo con plantillas y guías de contraseñas.", 25, "kit.jpg", "Otros", 500),
            ("Accesorio CableShield", "Organizador de cables con material resistente al desgaste.", 18, "cables.jpg", "Otros", 400),
            ("Plantilla Auditoría Express", "Plantilla imprimible para auditoría básica de seguridad.", 12, "plantilla.jpg", "Otros", 600),
        ])
        print("Productos de prueba inyectados correctamente.")

    conn.commit()
    conn.close()


# AUTOMATIZACIÓN SEGURA: Inicializa la base de datos al arrancar la app si el archivo no existe
with app.app_context():
    init_db()

if __name__ == "__main__":
    app.run(debug=True)
