"""Enrollment Event database model."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID  # noqa: TC003

from sqlalchemy import ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base

if TYPE_CHECKING:
    from .est_profile import ESTProfile


class EnrollmentEvent(Base):
    """Certificate enrollment event log."""

    __tablename__ = "enrollment_events"
    __table_args__ = (
        Index("idx_enrollment_event_profile", "profile_id"),
        Index("idx_enrollment_event_status", "status"),
        Index("idx_enrollment_event_device", "device_id"),
        Index("idx_enrollment_event_correlation", "correlation_id"),
        Index("idx_enrollment_event_timestamp", "created_at"),
    )

    profile_id: Mapped[UUID] = mapped_column(ForeignKey("est_profiles.id"), nullable=False)
    device_id: Mapped[str | None] = mapped_column(String(255))
    subject_dn: Mapped[str | None] = mapped_column(String(500))
    status: Mapped[str] = mapped_column(String(50), nullable=False)  # 'pending', 'approved', 'rejected', 'error'
    error_message: Mapped[str | None] = mapped_column(Text)
    ip_address: Mapped[str | None] = mapped_column(String(45))  # IPv6 compatible
    user_agent: Mapped[str | None] = mapped_column(Text)
    request_id: Mapped[str | None] = mapped_column(String(255))
    correlation_id: Mapped[str | None] = mapped_column(String(255))

    # Relationships
    profile: Mapped[ESTProfile] = relationship("ESTProfile", back_populates="enrollment_events", lazy="joined")

    def __repr__(self) -> str:
        return f"<EnrollmentEvent(profile_id='{self.profile_id}', status='{self.status}')>"
