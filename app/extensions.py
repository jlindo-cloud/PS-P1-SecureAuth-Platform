from authlib.integrations.flask_client import OAuth
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_talisman import Talisman
from flask_wtf import CSRFProtect
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


db = SQLAlchemy(model_class=Base)
migrate = Migrate()
csrf = CSRFProtect()
oauth = OAuth()
talisman = Talisman()

# Los límites globales protegen contra abuso, pero deben dejar
# margen para el uso normal: cada carga del catálogo genera una
# petición por el HTML más una por cada imagen y hoja de estilo.
# Con 300/día una sola persona agotaba su cuota en unas 20
# visitas. Los archivos estáticos quedan exentos (ver
# app/__init__.py), y estos límites cubren solo las vistas.
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[
        "2000 per day",
        "300 per hour",
    ],
)