"""CA Backend database model."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    JSON,  # SQLite-compatible JSON type
    Boolean,
    Index,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base

if TYPE_CHECKING:
    from .est_profile import ESTProfile


class CABackend(Base):
    """Certificate Authority backend configuration."""

    __tablename__ = "ca_backends"
    __table_args__ = (
        UniqueConstraint("name", name="uq_ca_backend_name"),
        Index("idx_ca_backend_type", "type"),
        Index("idx_ca_backend_enabled", "is_enabled"),
    )

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    type: Mapped[str] = mapped_column(String(50), nullable=False)  # 'self_signed', 'acme', 'scep'
    config: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    description: Mapped[str | None] = mapped_column(Text)

    # Relationships
    est_profiles: Mapped[list["ESTProfile"]] = relationship("ESTProfile", back_populates="ca_backend", lazy="selectin")  # noqa: F821

    def __repr__(self) -> str:
        return f"<CABackend(name='{self.name}', type='{self.type}')>"
