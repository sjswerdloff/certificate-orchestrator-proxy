"""EST Profile database model."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from uuid import UUID

from sqlalchemy import (
    JSON,  # SQLite-compatible JSON type
    Boolean,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base

if TYPE_CHECKING:
    from .ca_backend import CABackend
    from .enrollment_event import EnrollmentEvent


class ESTProfile(Base):
    """EST endpoint profile configuration."""

    __tablename__ = "est_profiles"
    __table_args__ = (
        UniqueConstraint("name", name="uq_est_profile_name"),
        Index("idx_est_profile_ca_backend", "ca_backend_id"),
        Index("idx_est_profile_enabled", "is_enabled"),
    )

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    ca_backend_id: Mapped[UUID] = mapped_column(ForeignKey("ca_backends.id"), nullable=False)
    allowed_subjects: Mapped[list[str] | None] = mapped_column(JSON)
    validation_rules: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    description: Mapped[str | None] = mapped_column(Text)

    # Relationships
    ca_backend: Mapped["CABackend"] = relationship("CABackend", back_populates="est_profiles", lazy="joined")  # noqa: F821
    enrollment_events: Mapped[list["EnrollmentEvent"]] = relationship(  # noqa: F821
        "EnrollmentEvent", back_populates="profile", lazy="selectin"
    )

    def __repr__(self) -> str:
        return f"<ESTProfile(name='{self.name}', ca_backend_id='{self.ca_backend_id}')>"
