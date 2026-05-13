"""Unit tests for admin API Pydantic schemas.

These tests exercise validation logic directly — no HTTP layer, no database.
The goal is to verify that each validator rejects exactly what it should reject,
accepts what it should accept, and that error messages identify the correct field.

Medical-software quality bar: assertions check field name and error type, not
just "raises something". A validator that silently accepts bad data is as
dangerous as one that crashes.
"""

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from est_adapter.admin.schemas.ca_backend import (
    CABackendCreate,
    CABackendResponse,
    CABackendUpdate,
)
from est_adapter.admin.schemas.enrollment_event import (
    EnrollmentEventCreate,
    EnrollmentEventFilter,
    EnrollmentEventResponse,
)
from est_adapter.admin.schemas.est_profile import (
    ESTProfileCreate,
    ESTProfileResponse,
    ESTProfileUpdate,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_VALID_UUID = uuid4()
_NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


def _error_fields(exc: ValidationError) -> list[str]:
    """Return the list of field names that failed validation."""
    return [str(e["loc"][-1]) for e in exc.errors()]


def _error_messages(exc: ValidationError) -> list[str]:
    return [e["msg"] for e in exc.errors()]


# ===========================================================================
# CABackend schemas
# ===========================================================================


class TestCABackendCreate:
    """Happy-path and validation tests for CABackendCreate."""

    def test_valid_self_signed(self) -> None:
        """Accept a minimal valid CABackendCreate with type self_signed."""
        backend = CABackendCreate(name="my-ca", type="self_signed")
        assert backend.name == "my-ca"
        assert backend.type == "self_signed"
        assert backend.is_enabled is True
        assert backend.config == {}

    def test_valid_acme(self) -> None:
        """Accept type acme."""
        backend = CABackendCreate(name="acme-ca", type="acme", config={"url": "https://acme.example.com"})
        assert backend.type == "acme"

    def test_valid_scep(self) -> None:
        """Accept type scep."""
        backend = CABackendCreate(name="scep-ca", type="scep")
        assert backend.type == "scep"

    def test_invalid_type_rejected(self) -> None:
        """Reject an unsupported CA type."""
        with pytest.raises(ValidationError) as exc_info:
            CABackendCreate(name="bad-ca", type="unknown_type")
        err = exc_info.value
        assert "type" in _error_fields(err)
        assert any("Type must be one of" in m for m in _error_messages(err))

    def test_name_alphanumeric_with_dash_underscore(self) -> None:
        """Accept names with letters, digits, hyphens, and underscores."""
        for name in ("a", "A1", "my-ca", "my_ca", "CA-123_test"):
            backend = CABackendCreate(name=name, type="self_signed")
            assert backend.name == name

    def test_name_with_space_rejected(self) -> None:
        """Reject names containing spaces (pattern constraint)."""
        with pytest.raises(ValidationError) as exc_info:
            CABackendCreate(name="my ca", type="self_signed")
        assert "name" in _error_fields(exc_info.value)

    def test_name_with_dot_rejected(self) -> None:
        """Reject names containing dots (pattern constraint)."""
        with pytest.raises(ValidationError) as exc_info:
            CABackendCreate(name="my.ca", type="self_signed")
        assert "name" in _error_fields(exc_info.value)

    def test_name_empty_rejected(self) -> None:
        """Reject empty name (min_length=1)."""
        with pytest.raises(ValidationError) as exc_info:
            CABackendCreate(name="", type="self_signed")
        assert "name" in _error_fields(exc_info.value)

    def test_name_max_length_accepted(self) -> None:
        """Accept name exactly at max_length=255."""
        name = "a" * 255
        backend = CABackendCreate(name=name, type="self_signed")
        assert len(backend.name) == 255

    def test_name_over_max_length_rejected(self) -> None:
        """Reject name exceeding max_length=255."""
        with pytest.raises(ValidationError) as exc_info:
            CABackendCreate(name="a" * 256, type="self_signed")
        assert "name" in _error_fields(exc_info.value)

    def test_description_optional(self) -> None:
        """Description defaults to None."""
        backend = CABackendCreate(name="ca", type="self_signed")
        assert backend.description is None

    def test_description_accepted(self) -> None:
        """Accept a description string."""
        backend = CABackendCreate(name="ca", type="self_signed", description="A test CA")
        assert backend.description == "A test CA"

    def test_description_over_max_rejected(self) -> None:
        """Reject description over max_length=1000."""
        with pytest.raises(ValidationError) as exc_info:
            CABackendCreate(name="ca", type="self_signed", description="x" * 1001)
        assert "description" in _error_fields(exc_info.value)

    def test_is_enabled_defaults_true(self) -> None:
        """is_enabled defaults to True."""
        backend = CABackendCreate(name="ca", type="self_signed")
        assert backend.is_enabled is True

    def test_is_enabled_false(self) -> None:
        """Accept is_enabled=False."""
        backend = CABackendCreate(name="ca", type="self_signed", is_enabled=False)
        assert backend.is_enabled is False

    def test_extra_fields_rejected(self) -> None:
        """extra='forbid' — extra fields must be rejected."""
        with pytest.raises(ValidationError):
            CABackendCreate(name="ca", type="self_signed", unknown_field="oops")


class TestCABackendUpdate:
    """Tests for CABackendUpdate — all fields optional, type validator handles None."""

    def test_empty_update_accepted(self) -> None:
        """An empty update (all None) is valid — nothing to change."""
        update = CABackendUpdate()
        assert update.name is None
        assert update.type is None

    def test_valid_type_update(self) -> None:
        """Accept a valid type in an update."""
        update = CABackendUpdate(type="acme")
        assert update.type == "acme"

    def test_invalid_type_update_rejected(self) -> None:
        """Reject invalid type in an update."""
        with pytest.raises(ValidationError) as exc_info:
            CABackendUpdate(type="bad_type")
        err = exc_info.value
        assert "type" in _error_fields(err)
        assert any("Type must be one of" in m for m in _error_messages(err))

    def test_type_none_accepted(self) -> None:
        """Explicit None for type is allowed (means don't update type)."""
        update = CABackendUpdate(type=None)
        assert update.type is None

    def test_name_none_accepted(self) -> None:
        """Explicit None for name is allowed."""
        update = CABackendUpdate(name=None)
        assert update.name is None

    def test_name_invalid_pattern_rejected(self) -> None:
        """Pattern constraint applies in updates too."""
        with pytest.raises(ValidationError) as exc_info:
            CABackendUpdate(name="bad name!")
        assert "name" in _error_fields(exc_info.value)

    def test_all_valid_fields(self) -> None:
        """Accept an update with all valid fields populated."""
        update = CABackendUpdate(
            name="new-name",
            type="scep",
            config={"key": "val"},
            is_enabled=False,
            description="updated",
        )
        assert update.name == "new-name"
        assert update.type == "scep"
        assert update.is_enabled is False


class TestCABackendResponse:
    """Tests for CABackendResponse (includes id, timestamps)."""

    def test_valid_response(self) -> None:
        """Construct a valid response object."""
        resp = CABackendResponse(
            id=_VALID_UUID,
            name="test-ca",
            type="self_signed",
            created_at=_NOW,
            updated_at=_NOW,
        )
        assert resp.id == _VALID_UUID
        assert resp.est_profiles_count is None

    def test_response_with_profiles_count(self) -> None:
        """est_profiles_count is optional; accept a non-None value."""
        resp = CABackendResponse(
            id=_VALID_UUID,
            name="test-ca",
            type="self_signed",
            created_at=_NOW,
            updated_at=_NOW,
            est_profiles_count=5,
        )
        assert resp.est_profiles_count == 5

    def test_response_extra_fields_rejected(self) -> None:
        """extra='forbid' applies to response schema."""
        with pytest.raises(ValidationError):
            CABackendResponse(
                id=_VALID_UUID,
                name="test-ca",
                type="self_signed",
                created_at=_NOW,
                updated_at=_NOW,
                surprise_field="nope",
            )


# ===========================================================================
# ESTProfile schemas
# ===========================================================================


class TestESTProfileCreate:
    """Happy-path and validation tests for ESTProfileCreate."""

    def test_valid_minimal(self) -> None:
        """Accept minimal valid ESTProfileCreate."""
        profile = ESTProfileCreate(name="my-profile", ca_backend_id=_VALID_UUID)
        assert profile.name == "my-profile"
        assert profile.ca_backend_id == _VALID_UUID
        assert profile.is_enabled is True
        assert profile.allowed_subjects is None
        assert profile.validation_rules is None

    def test_name_pattern_enforced(self) -> None:
        """Reject names with invalid characters."""
        with pytest.raises(ValidationError) as exc_info:
            ESTProfileCreate(name="bad name!", ca_backend_id=_VALID_UUID)
        assert "name" in _error_fields(exc_info.value)

    def test_name_empty_rejected(self) -> None:
        """Reject empty name."""
        with pytest.raises(ValidationError) as exc_info:
            ESTProfileCreate(name="", ca_backend_id=_VALID_UUID)
        assert "name" in _error_fields(exc_info.value)

    def test_allowed_subjects_within_limit(self) -> None:
        """Accept allowed_subjects up to and including 100 entries."""
        subjects = [f"CN=device-{i}" for i in range(100)]
        profile = ESTProfileCreate(name="p", ca_backend_id=_VALID_UUID, allowed_subjects=subjects)
        assert len(profile.allowed_subjects) == 100  # type: ignore[arg-type]

    def test_allowed_subjects_over_limit_rejected(self) -> None:
        """Reject allowed_subjects with more than 100 entries.

        Pydantic's Field(max_length=100) fires before the custom validator,
        producing a structured too_long error with loc, type, and ctx.max_length.
        The redundant in-validator length check has been removed; this test
        asserts the Field constraint is the sole enforcement point.
        """
        subjects = [f"CN=device-{i}" for i in range(101)]
        with pytest.raises(ValidationError) as exc_info:
            ESTProfileCreate(name="p", ca_backend_id=_VALID_UUID, allowed_subjects=subjects)
        err = exc_info.value
        assert "allowed_subjects" in _error_fields(err)
        # Error comes from the field max_length constraint (too_long), not a free-text ValueError
        assert any(e["type"] == "too_long" for e in err.errors())

    def test_allowed_subjects_none_accepted(self) -> None:
        """Explicit None for allowed_subjects is valid."""
        profile = ESTProfileCreate(name="p", ca_backend_id=_VALID_UUID, allowed_subjects=None)
        assert profile.allowed_subjects is None

    def test_allowed_subjects_empty_list_accepted(self) -> None:
        """Empty list passes the >100 check."""
        profile = ESTProfileCreate(name="p", ca_backend_id=_VALID_UUID, allowed_subjects=[])
        assert profile.allowed_subjects == []

    def test_validation_rules_accepts_arbitrary_dict(self) -> None:
        """validation_rules accepts any dict."""
        rules = {"max_validity": 365, "require_san": True}
        profile = ESTProfileCreate(name="p", ca_backend_id=_VALID_UUID, validation_rules=rules)
        assert profile.validation_rules == rules

    def test_description_max_length(self) -> None:
        """Reject description over max_length=1000."""
        with pytest.raises(ValidationError) as exc_info:
            ESTProfileCreate(name="p", ca_backend_id=_VALID_UUID, description="x" * 1001)
        assert "description" in _error_fields(exc_info.value)

    def test_extra_fields_rejected(self) -> None:
        """extra='forbid' in base config."""
        with pytest.raises(ValidationError):
            ESTProfileCreate(name="p", ca_backend_id=_VALID_UUID, extra_junk="bad")


class TestESTProfileUpdate:
    """Tests for ESTProfileUpdate — all fields optional."""

    def test_empty_update_accepted(self) -> None:
        """All-None update is valid."""
        update = ESTProfileUpdate()
        assert update.name is None
        assert update.ca_backend_id is None

    def test_allowed_subjects_over_limit_rejected_in_update(self) -> None:
        """allowed_subjects > 100 also rejected in update context.

        Same as ESTProfileCreate — the Field(max_length=100) constraint fires
        before the custom validator, producing a structured too_long error.
        The redundant in-validator length check has been removed.
        """
        subjects = [f"CN=device-{i}" for i in range(101)]
        with pytest.raises(ValidationError) as exc_info:
            ESTProfileUpdate(allowed_subjects=subjects)
        err = exc_info.value
        assert "allowed_subjects" in _error_fields(err)
        assert any(e["type"] == "too_long" for e in err.errors())

    def test_allowed_subjects_none_in_update_accepted(self) -> None:
        """Explicit None for allowed_subjects is valid in update."""
        update = ESTProfileUpdate(allowed_subjects=None)
        assert update.allowed_subjects is None

    def test_allowed_subjects_exactly_100_in_update_accepted(self) -> None:
        """exactly 100 entries must pass."""
        subjects = [f"CN=device-{i}" for i in range(100)]
        update = ESTProfileUpdate(allowed_subjects=subjects)
        assert len(update.allowed_subjects) == 100  # type: ignore[arg-type]

    def test_name_pattern_in_update(self) -> None:
        """Pattern still enforced in update."""
        with pytest.raises(ValidationError) as exc_info:
            ESTProfileUpdate(name="bad name!")
        assert "name" in _error_fields(exc_info.value)

    def test_is_enabled_update(self) -> None:
        """Accept is_enabled in an update."""
        update = ESTProfileUpdate(is_enabled=False)
        assert update.is_enabled is False


class TestESTProfileResponse:
    """Tests for ESTProfileResponse."""

    def test_valid_response(self) -> None:
        """Construct a valid response."""
        resp = ESTProfileResponse(
            id=_VALID_UUID,
            name="test-profile",
            ca_backend_id=_VALID_UUID,
            created_at=_NOW,
            updated_at=_NOW,
        )
        assert resp.id == _VALID_UUID
        assert resp.enrollment_events_count is None

    def test_enrollment_events_count_populated(self) -> None:
        """Accept enrollment_events_count."""
        resp = ESTProfileResponse(
            id=_VALID_UUID,
            name="test-profile",
            ca_backend_id=_VALID_UUID,
            created_at=_NOW,
            updated_at=_NOW,
            enrollment_events_count=42,
        )
        assert resp.enrollment_events_count == 42


# ===========================================================================
# EnrollmentEvent schemas
# ===========================================================================


class TestEnrollmentEventCreate:
    """Happy-path and validation tests for EnrollmentEventCreate."""

    def test_valid_minimal(self) -> None:
        """Accept minimal valid EnrollmentEventCreate."""
        event = EnrollmentEventCreate(profile_id=_VALID_UUID, status="pending")
        assert event.profile_id == _VALID_UUID
        assert event.status == "pending"
        assert event.device_id is None
        assert event.ip_address is None

    def test_all_valid_statuses(self) -> None:
        """Each allowed status value is accepted."""
        for status in ("pending", "approved", "rejected", "error"):
            event = EnrollmentEventCreate(profile_id=_VALID_UUID, status=status)
            assert event.status == status

    def test_invalid_status_rejected(self) -> None:
        """A status not in the valid set must be rejected."""
        with pytest.raises(ValidationError) as exc_info:
            EnrollmentEventCreate(profile_id=_VALID_UUID, status="unknown")
        err = exc_info.value
        assert "status" in _error_fields(err)
        assert any("Status must be one of" in m for m in _error_messages(err))

    def test_status_empty_string_rejected(self) -> None:
        """Empty string fails min_length=1 before reaching the validator."""
        with pytest.raises(ValidationError) as exc_info:
            EnrollmentEventCreate(profile_id=_VALID_UUID, status="")
        assert "status" in _error_fields(exc_info.value)

    def test_status_case_sensitive(self) -> None:
        """Status is case-sensitive — 'Pending' is not 'pending'."""
        with pytest.raises(ValidationError) as exc_info:
            EnrollmentEventCreate(profile_id=_VALID_UUID, status="Pending")
        assert "status" in _error_fields(exc_info.value)

    # --- IP address validator ---

    def test_valid_ipv4(self) -> None:
        """Accept a valid IPv4 address."""
        event = EnrollmentEventCreate(profile_id=_VALID_UUID, status="pending", ip_address="192.168.1.1")
        assert event.ip_address == "192.168.1.1"

    def test_valid_ipv4_boundary_255(self) -> None:
        """Accept 255.255.255.255 (max IPv4 octet values)."""
        event = EnrollmentEventCreate(profile_id=_VALID_UUID, status="pending", ip_address="255.255.255.255")
        assert event.ip_address == "255.255.255.255"

    def test_valid_ipv4_all_zeros(self) -> None:
        """Accept 0.0.0.0."""
        event = EnrollmentEventCreate(profile_id=_VALID_UUID, status="pending", ip_address="0.0.0.0")
        assert event.ip_address == "0.0.0.0"

    def test_valid_ipv6(self) -> None:
        """Accept a valid full-form IPv6 address."""
        event = EnrollmentEventCreate(
            profile_id=_VALID_UUID,
            status="pending",
            ip_address="2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        )
        assert event.ip_address == "2001:0db8:85a3:0000:0000:8a2e:0370:7334"

    def test_ip_address_none_accepted(self) -> None:
        """None is accepted (optional field)."""
        event = EnrollmentEventCreate(profile_id=_VALID_UUID, status="pending", ip_address=None)
        assert event.ip_address is None

    def test_invalid_ip_address_rejected(self) -> None:
        """Reject a malformed IP address."""
        with pytest.raises(ValidationError) as exc_info:
            EnrollmentEventCreate(profile_id=_VALID_UUID, status="pending", ip_address="not-an-ip")
        err = exc_info.value
        assert "ip_address" in _error_fields(err)
        assert any("Invalid IP address format" in m for m in _error_messages(err))

    def test_ip_address_with_port_rejected(self) -> None:
        """Reject IP:port format — not a bare IP address."""
        with pytest.raises(ValidationError) as exc_info:
            EnrollmentEventCreate(profile_id=_VALID_UUID, status="pending", ip_address="192.168.1.1:8080")
        assert "ip_address" in _error_fields(exc_info.value)

    def test_ip_address_octet_out_of_range_rejected(self) -> None:
        """Reject IPv4 address with octet > 255."""
        with pytest.raises(ValidationError) as exc_info:
            EnrollmentEventCreate(profile_id=_VALID_UUID, status="pending", ip_address="999.0.0.1")
        assert "ip_address" in _error_fields(exc_info.value)

    def test_ip_address_compressed_ipv6_accepted(self) -> None:
        """Compressed IPv6 notation is now accepted via stdlib ipaddress validation.

        The previous regex required exactly 8 colon-separated groups and rejected all
        abbreviated forms. The validator now uses ipaddress.ip_address() which correctly
        handles all standard IPv6 compressed notation, including loopback (::1) and
        prefix-abbreviated forms like 2001:db8::1.
        """
        event = EnrollmentEventCreate(profile_id=_VALID_UUID, status="pending", ip_address="::1")
        assert event.ip_address == "::1"

        event2 = EnrollmentEventCreate(profile_id=_VALID_UUID, status="pending", ip_address="2001:db8::1")
        assert event2.ip_address == "2001:db8::1"

    def test_device_id_max_length(self) -> None:
        """Reject device_id over max_length=255."""
        with pytest.raises(ValidationError) as exc_info:
            EnrollmentEventCreate(profile_id=_VALID_UUID, status="pending", device_id="x" * 256)
        assert "device_id" in _error_fields(exc_info.value)

    def test_device_id_at_max_length_accepted(self) -> None:
        """Accept device_id exactly at max_length=255."""
        event = EnrollmentEventCreate(profile_id=_VALID_UUID, status="pending", device_id="d" * 255)
        assert len(event.device_id) == 255  # type: ignore[arg-type]

    def test_subject_dn_max_length(self) -> None:
        """Reject subject_dn over max_length=500."""
        with pytest.raises(ValidationError) as exc_info:
            EnrollmentEventCreate(profile_id=_VALID_UUID, status="pending", subject_dn="x" * 501)
        assert "subject_dn" in _error_fields(exc_info.value)

    def test_request_id_max_length(self) -> None:
        """Reject request_id over max_length=255."""
        with pytest.raises(ValidationError) as exc_info:
            EnrollmentEventCreate(profile_id=_VALID_UUID, status="pending", request_id="x" * 256)
        assert "request_id" in _error_fields(exc_info.value)

    def test_correlation_id_accepted(self) -> None:
        """Accept a correlation_id."""
        event = EnrollmentEventCreate(
            profile_id=_VALID_UUID,
            status="pending",
            correlation_id="corr-abc-123",
        )
        assert event.correlation_id == "corr-abc-123"

    def test_error_message_accepted_with_error_status(self) -> None:
        """Accept error_message when status is 'error'."""
        event = EnrollmentEventCreate(
            profile_id=_VALID_UUID,
            status="error",
            error_message="CA unreachable",
        )
        assert event.error_message == "CA unreachable"

    def test_extra_fields_rejected(self) -> None:
        """extra='forbid' applies."""
        with pytest.raises(ValidationError):
            EnrollmentEventCreate(profile_id=_VALID_UUID, status="pending", not_a_field="bad")


class TestEnrollmentEventResponse:
    """Tests for EnrollmentEventResponse."""

    def test_valid_response(self) -> None:
        """Construct a valid response."""
        resp = EnrollmentEventResponse(
            id=_VALID_UUID,
            profile_id=_VALID_UUID,
            status="approved",
            created_at=_NOW,
            updated_at=_NOW,
        )
        assert resp.id == _VALID_UUID
        assert resp.status == "approved"

    def test_response_extra_fields_rejected(self) -> None:
        """extra='forbid' on response."""
        with pytest.raises(ValidationError):
            EnrollmentEventResponse(
                id=_VALID_UUID,
                profile_id=_VALID_UUID,
                status="approved",
                created_at=_NOW,
                updated_at=_NOW,
                unknown="bad",
            )


class TestEnrollmentEventFilter:
    """Tests for EnrollmentEventFilter — all fields optional."""

    def test_empty_filter_accepted(self) -> None:
        """An empty filter (all None defaults) is valid."""
        f = EnrollmentEventFilter()
        assert f.profile_id is None
        assert f.status is None
        assert f.ip_address is None

    def test_valid_status_filter(self) -> None:
        """Each valid status is accepted in a filter."""
        for status in ("pending", "approved", "rejected", "error"):
            f = EnrollmentEventFilter(status=status)
            assert f.status == status

    def test_invalid_status_filter_rejected(self) -> None:
        """Invalid status in filter must be rejected."""
        with pytest.raises(ValidationError) as exc_info:
            EnrollmentEventFilter(status="bad_status")
        err = exc_info.value
        assert "status" in _error_fields(err)
        assert any("Status must be one of" in m for m in _error_messages(err))

    def test_status_none_in_filter_accepted(self) -> None:
        """Explicit None for status is valid (means don't filter by status)."""
        f = EnrollmentEventFilter(status=None)
        assert f.status is None

    def test_valid_ip_in_filter(self) -> None:
        """Accept a valid IPv4 in filter."""
        f = EnrollmentEventFilter(ip_address="10.0.0.1")
        assert f.ip_address == "10.0.0.1"

    def test_invalid_ip_in_filter_rejected(self) -> None:
        """Invalid IP rejected in filter."""
        with pytest.raises(ValidationError) as exc_info:
            EnrollmentEventFilter(ip_address="not-an-ip")
        err = exc_info.value
        assert "ip_address" in _error_fields(err)
        assert any("Invalid IP address format" in m for m in _error_messages(err))

    def test_ip_none_in_filter_accepted(self) -> None:
        """Explicit None for ip_address is valid in filter."""
        f = EnrollmentEventFilter(ip_address=None)
        assert f.ip_address is None

    def test_date_range_filter(self) -> None:
        """Accept start_date and end_date."""
        start = datetime(2026, 1, 1, tzinfo=UTC)
        end = datetime(2026, 12, 31, tzinfo=UTC)
        f = EnrollmentEventFilter(start_date=start, end_date=end)
        assert f.start_date == start
        assert f.end_date == end

    def test_filter_by_profile_id(self) -> None:
        """Accept a UUID for profile_id filter."""
        uid = uuid4()
        f = EnrollmentEventFilter(profile_id=uid)
        assert f.profile_id == uid

    def test_filter_device_id_max_length(self) -> None:
        """Reject device_id over max_length=255 in filter."""
        with pytest.raises(ValidationError) as exc_info:
            EnrollmentEventFilter(device_id="x" * 256)
        assert "device_id" in _error_fields(exc_info.value)

    def test_filter_request_id_accepted(self) -> None:
        """Accept request_id in filter."""
        f = EnrollmentEventFilter(request_id="req-abc-123")
        assert f.request_id == "req-abc-123"

    def test_filter_subject_dn_accepted(self) -> None:
        """Accept subject_dn in filter."""
        f = EnrollmentEventFilter(subject_dn="CN=device-001,O=Acme,C=US")
        assert f.subject_dn == "CN=device-001,O=Acme,C=US"

    def test_filter_correlation_id_accepted(self) -> None:
        """Accept correlation_id in filter."""
        f = EnrollmentEventFilter(correlation_id="corr-xyz-789")
        assert f.correlation_id == "corr-xyz-789"


# ===========================================================================
# Cross-schema / edge-case observations documented as tests
# ===========================================================================


class TestSchemaObservations:
    """Tests that document observed behavior, including potential gaps.

    These tests serve as regression anchors. When a finding is noted in a
    test docstring as a FINDING, it describes real behavior observed — not
    a test failure. The test passes if the behavior is as documented.
    """

    def test_enrollment_event_status_max_length_fires_before_custom_validator(self) -> None:
        """FINDING: For status strings longer than 50 characters, Pydantic's
        built-in max_length constraint fires first and produces a 'string_too_long'
        error — the custom validate_status validator is never reached for inputs
        that violate max_length. The max_length=50 and the custom validator
        together provide layered defense, but the validator's unreachable path
        for length-exceeding inputs is a minor dead-branch observation.
        """
        # 51-char string hits max_length=50 before the custom validator
        with pytest.raises(ValidationError) as exc_info:
            EnrollmentEventCreate(profile_id=_VALID_UUID, status="x" * 51)
        err = exc_info.value
        assert "status" in _error_fields(err)
        # The field constraint fires, producing a string_too_long error
        assert any("50" in m for m in _error_messages(err))

    def test_ip_address_max_length_45_enforced_before_validator(self) -> None:
        """max_length=45 is sufficient for full IPv6 (39 chars) and IPv4-mapped
        IPv6 (e.g. '::ffff:192.168.1.1' = 18 chars). The field length limit
        is appropriate for the stated purpose.
        """
        # A 46-character string would hit max_length before the ip validator
        with pytest.raises(ValidationError) as exc_info:
            EnrollmentEventCreate(profile_id=_VALID_UUID, status="pending", ip_address="1" * 46)
        # At 46 chars the length constraint fires
        assert "ip_address" in _error_fields(exc_info.value)

    def test_ca_backend_type_validator_none_branch_in_update(self) -> None:
        """Explicitly test the None-early-return branch in CABackendUpdate.validate_type.

        This covers the 'if v is None: return v' path that was missing from coverage.
        """
        update = CABackendUpdate(type=None)
        assert update.type is None

    def test_enrollment_filter_ip_validator_none_branch(self) -> None:
        """Explicitly test the None-early-return branch in EnrollmentEventFilter.validate_ip_address."""
        f = EnrollmentEventFilter(ip_address=None)
        assert f.ip_address is None

    def test_enrollment_filter_status_validator_none_branch(self) -> None:
        """Explicitly test the None-early-return branch in EnrollmentEventFilter.validate_status."""
        f = EnrollmentEventFilter(status=None)
        assert f.status is None

    def test_est_profile_base_str_strip_whitespace(self) -> None:
        """Verify str_strip_whitespace config strips leading/trailing spaces from name.

        FINDING: Because name has a pattern=r'^[a-zA-Z0-9_-]+$' constraint,
        a name with surrounding whitespace will FAIL pattern validation
        AFTER stripping — so '  myprofile  ' becomes 'myprofile' (valid).
        But a name that is purely whitespace becomes '' and fails min_length.
        """
        # Leading/trailing whitespace is stripped before pattern validation
        profile = ESTProfileCreate(name="  myprofile  ", ca_backend_id=_VALID_UUID)
        assert profile.name == "myprofile"

    def test_ca_backend_name_strip_whitespace(self) -> None:
        """Whitespace stripping applies to CA backend names too."""
        backend = CABackendCreate(name="  my-ca  ", type="self_signed")
        assert backend.name == "my-ca"

    def test_enrollment_event_user_agent_at_max_length_accepted(self) -> None:
        """user_agent at exactly max_length=512 is accepted."""
        ua_512 = "Mozilla/" + "X" * 504
        assert len(ua_512) == 512
        event = EnrollmentEventCreate(profile_id=_VALID_UUID, status="pending", user_agent=ua_512)
        assert event.user_agent == ua_512

    def test_enrollment_event_user_agent_over_max_length_rejected(self) -> None:
        """user_agent at 513 chars is rejected with string_too_long error."""
        ua_513 = "Mozilla/" + "X" * 505
        assert len(ua_513) == 513
        with pytest.raises(ValidationError) as exc_info:
            EnrollmentEventCreate(profile_id=_VALID_UUID, status="pending", user_agent=ua_513)
        err = exc_info.value
        assert "user_agent" in _error_fields(err)
        assert any(e["type"] == "string_too_long" for e in err.errors())

    def test_enrollment_event_error_message_at_max_length_accepted(self) -> None:
        """error_message at exactly max_length=4096 is accepted."""
        msg_4096 = "Error: " + "x" * 4089
        assert len(msg_4096) == 4096
        event = EnrollmentEventCreate(profile_id=_VALID_UUID, status="error", error_message=msg_4096)
        assert event.error_message == msg_4096

    def test_enrollment_event_error_message_over_max_length_rejected(self) -> None:
        """error_message at 4097 chars is rejected with string_too_long error."""
        msg_4097 = "Error: " + "x" * 4090
        assert len(msg_4097) == 4097
        with pytest.raises(ValidationError) as exc_info:
            EnrollmentEventCreate(profile_id=_VALID_UUID, status="error", error_message=msg_4097)
        err = exc_info.value
        assert "error_message" in _error_fields(err)
        assert any(e["type"] == "string_too_long" for e in err.errors())
