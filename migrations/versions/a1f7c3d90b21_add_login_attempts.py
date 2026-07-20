"""Historial de intentos de acceso para el motor Zero-Trust

Revision ID: a1f7c3d90b21
Revises: 6f7ff72e7eab
Create Date: 2026-07-20

Crea la tabla que alimenta el análisis de comportamiento de
app/anomaly_detector.py. La dirección IP se almacena hasheada,
no en claro.
"""

import sqlalchemy as sa
from alembic import op


revision = "a1f7c3d90b21"
down_revision = "6f7ff72e7eab"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "login_attempts",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("email", sa.String(length=254), nullable=False),
        sa.Column("success", sa.Boolean(), nullable=False),
        sa.Column("ip_hash", sa.String(length=64), nullable=True),
        sa.Column("user_agent", sa.String(length=300), nullable=True),
        sa.Column("hour_of_day", sa.Integer(), nullable=True),
        sa.Column("day_of_week", sa.Integer(), nullable=True),
        sa.Column("risk_score", sa.Float(), nullable=True),
        sa.Column("risk_level", sa.String(length=10), nullable=True),
        sa.Column("risk_method", sa.String(length=40), nullable=True),
        sa.Column("risk_factors", sa.String(length=500), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_index(
        "ix_login_attempts_email",
        "login_attempts",
        ["email"],
    )
    op.create_index(
        "ix_login_attempts_created_at",
        "login_attempts",
        ["created_at"],
    )
    op.create_index(
        "ix_login_attempts_email_created",
        "login_attempts",
        ["email", "created_at"],
    )


def downgrade():
    op.drop_index("ix_login_attempts_email_created", table_name="login_attempts")
    op.drop_index("ix_login_attempts_created_at", table_name="login_attempts")
    op.drop_index("ix_login_attempts_email", table_name="login_attempts")
    op.drop_table("login_attempts")
