"""Add users table and extend cases with RBAC + EML storage columns

Revision ID: a1b2c3d4e5f6
Revises: 50566eee0d78
Create Date: 2026-09-05 18:00:00.000000

Changes:
  - NEW TABLE: users (id, email, hashed_password, role, is_active, created_at, last_login)
  - ALTER cases: + eml_sha256 (VARCHAR 64, nullable)
  - ALTER cases: + eml_storage_path (VARCHAR 512, nullable)
  - ALTER cases: + user_id (VARCHAR 36, nullable FK → users.id)
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, Sequence[str], None] = '50566eee0d78'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create users table and extend cases table."""
    # ── users ──────────────────────────────────────────────────────────────
    op.create_table(
        'users',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('hashed_password', sa.String(length=255), nullable=False),
        sa.Column('role', sa.String(length=20), nullable=False, server_default='analyst'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_login', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=True)

    # ── cases: EML preservation columns ────────────────────────────────────
    op.add_column('cases', sa.Column('eml_sha256', sa.String(length=64), nullable=True))
    op.add_column('cases', sa.Column('eml_storage_path', sa.String(length=512), nullable=True))

    # ── cases: RBAC user_id FK ─────────────────────────────────────────────
    op.add_column('cases', sa.Column('user_id', sa.String(length=36), nullable=True))
    op.create_index(op.f('ix_cases_user_id'), 'cases', ['user_id'], unique=False)
    op.create_foreign_key(
        'fk_cases_user_id',
        'cases', 'users',
        ['user_id'], ['id'],
        ondelete='SET NULL',
    )


def downgrade() -> None:
    """Revert users table and case column additions."""
    # Drop FK + index + column from cases
    op.drop_constraint('fk_cases_user_id', 'cases', type_='foreignkey')
    op.drop_index(op.f('ix_cases_user_id'), table_name='cases')
    op.drop_column('cases', 'user_id')
    op.drop_column('cases', 'eml_storage_path')
    op.drop_column('cases', 'eml_sha256')

    # Drop users table
    op.drop_index(op.f('ix_users_email'), table_name='users')
    op.drop_table('users')
