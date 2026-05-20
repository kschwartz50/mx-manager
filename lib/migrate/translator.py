"""MX-specific PAN-OS translator.

Converts pre-resolved MX firewall term data into PAN-OS security rule models.
The mapper is responsible for resolving address objects, prefix-list groups,
service objects, and zone names before calling this translator.  The
translator's job is purely to assemble those resolved names into a valid
PolicyTranslationResult.

Design notes:
  - Zones are passed in from the mapper (derived from interface filter-application
    stanzas).  When not supplied, they fall back to ['any'].
  - Application vs service logic mirrors the srx-manager convention:
      * Explicit service objects  → application='any', service=[...]
      * Built-in App-IDs only     → application=[...], service='application-default'
      * Nothing                   → application='any', service='application-default'
  - All warned rules are still emitted with INVALID_RULE tag so they remain
    visible for human review rather than being silently dropped.
"""

import re
from typing import Any, Dict, List, Literal, Optional, Tuple

from lib.log_utils import get_logger
from lib.migrate.models import PanosSecurityRule, PolicyTranslationResult

logger = get_logger(__name__)


class MxPanosTranslator:
    """Translates pre-resolved MX firewall term data into PAN-OS security rules."""

    # Junos actions that produce a terminal security decision.
    TERMINAL_ACTIONS = {"accept", "reject", "discard"}

    # Junos actions that indicate a non-forwarding pass-through (skip term).
    NON_TERMINAL_ONLY_ACTIONS = {"next-term", "sample"}

    def is_terminal(self, actions: List[str]) -> bool:
        """Returns True if the action list contains at least one terminal action."""
        return any(a in self.TERMINAL_ACTIONS for a in actions)

    def map_action(self, actions: List[str]) -> Literal["allow", "deny", "drop"]:
        """Maps Junos terminal actions to PAN-OS rule action.

        Priority: accept > reject > discard.
        ``accept`` → allow
        ``reject`` → deny  (sends ICMP unreachable back to source)
        ``discard`` → drop  (silently drops)
        """
        if "accept" in actions:
            return "allow"
        if "reject" in actions:
            return "deny"
        if "discard" in actions:
            return "drop"
        return "deny"  # safe fallback

    def sanitize_name(self, name: str) -> str:
        """Normalizes a string to a valid PAN-OS object name.

        Rules:
          - Max 63 characters.
          - Allowed: letters, digits, spaces, hyphens, underscores, periods.
          - Must start with an alphanumeric character.
          - '/' → '_'; other illegal characters → '-'.
        """
        if not name:
            return "unknown"

        sanitized = name.replace("/", "_")
        sanitized = re.sub(r"[^a-zA-Z0-9 ._-]", "-", sanitized)
        sanitized = sanitized.lstrip(" ._-")

        if not sanitized:
            return "normalized-object"

        return sanitized[:63]

    def sanitize_rule_name(self, filter_name: str, term_name: str) -> str:
        """Builds a namespaced rule name from filter and term names.

        Format: ``{filter_name}_{term_name}`` (max 63 chars).
        The filter prefix disambiguates duplicate term names across filters.
        """
        combined = f"{filter_name}_{term_name}"
        return self.sanitize_name(combined)

    def sanitize_address_name(self, cidr: str) -> str:
        """Derives a valid PAN-OS address object name from a CIDR string.

        Example: '100.65.2.57/32' → '100.65.2.57_32'
        """
        return self.sanitize_name(cidr)

    def sanitize_prefix_list_name(self, raw_name: str) -> str:
        """Sanitizes a prefix-list name for use as a PAN-OS address group name."""
        return self.sanitize_name(raw_name)

    def _normalize_app_service_fields(
        self,
        *,
        applications: List[str],
        services: List[str],
    ) -> Tuple[List[str], List[str]]:
        """Normalizes application/service fields per PAN-OS mutual-exclusivity rules.

        PAN-OS convention used here:
          - Explicit services present  → application=['any'],  service=[...]
          - Built-in App-IDs only      → application=[...],   service=['application-default']
          - Neither                    → application=['any'],  service=['application-default']
        """
        if services:
            return ["any"], services

        if applications:
            return applications, ["application-default"]

        return ["any"], ["application-default"]

    def translate_firewall_term(
        self,
        term_data: Dict[str, Any],
    ) -> PolicyTranslationResult:
        """Converts a pre-resolved MX firewall term into a PAN-OS security rule.

        Expected keys in ``term_data``:
            filter_name (str)
            term_name (str)
            pan_name (str)                    — pre-built, namespaced rule name
            from_zones (List[str])            — PAN zone names or ['any']
            to_zones (List[str])              — PAN zone names or ['any']
            source_addresses (List[str])      — PAN address/group names or 'any'
            destination_addresses (List[str]) — PAN address/group names or 'any'
            applications (List[str])          — built-in PAN App-ID strings
            services (List[str])              — PAN service/service-group names
            action (str)                      — 'allow' | 'deny' | 'drop'
            description (Optional[str])
            log_end (bool)
            warnings (List[str])
        """
        source_name = str(term_data.get("term_name") or "unknown")
        pan_name = str(term_data.get("pan_name") or source_name)

        source_addresses = self._coerce_string_list(
            term_data.get("source_addresses", [])
        )
        destination_addresses = self._coerce_string_list(
            term_data.get("destination_addresses", [])
        )

        raw_applications = self._coerce_string_list(term_data.get("applications", []))
        raw_services = self._coerce_string_list(term_data.get("services", []))

        applications, services = self._normalize_app_service_fields(
            applications=raw_applications,
            services=raw_services,
        )

        action = str(term_data.get("action", "deny"))

        description = term_data.get("description")
        if not isinstance(description, str) or not description.strip():
            description = None

        log_end = bool(term_data.get("log_end", False))
        warnings: List[str] = self._coerce_string_list(term_data.get("warnings", []))

        # Default to empty list if not set; fallback to 'any'
        if not source_addresses:
            source_addresses = ["any"]
        if not destination_addresses:
            destination_addresses = ["any"]

        tags: List[str] = []
        if warnings:
            tags.append("INVALID_RULE")

        rendered_description = self._render_description(description, warnings)
        valid_pan_config = bool(pan_name)

        # Zones — use caller-supplied values; fall back to 'any' if absent.
        from_zones = self._coerce_string_list(term_data.get("from_zones", [])) or ["any"]
        to_zones = self._coerce_string_list(term_data.get("to_zones", [])) or ["any"]

        return PolicyTranslationResult(
            source_name=source_name,
            target_kind="security-rule",
            pan_name=pan_name,
            value=PanosSecurityRule(
                name=pan_name,
                from_zones=from_zones,
                to_zones=to_zones,
                source_addresses=source_addresses,
                destination_addresses=destination_addresses,
                applications=applications,
                services=services,
                action=action,
                description=rendered_description,
                disabled=False,
                tag=tags,
                log_start=False,
                log_end=log_end,
                warnings=warnings,
                valid_pan_config=valid_pan_config,
            ),
            warnings=warnings,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _coerce_string_list(self, value: Any) -> List[str]:
        if not isinstance(value, list):
            return []
        return [str(v).strip() for v in value if str(v).strip()]

    def _render_description(
        self,
        original: Optional[str],
        warnings: List[str],
    ) -> Optional[str]:
        """Combines the original description with any warning strings.

        Warnings are appended as '; '-separated segments so they are visible
        in the PAN-OS rule description field during post-migration review.
        """
        parts: List[str] = []

        if isinstance(original, str) and original.strip():
            parts.append(original.strip())

        for w in warnings:
            if isinstance(w, str) and w.strip():
                parts.append(w.strip())

        if not parts:
            return None

        return "; ".join(parts)


# end of lib/migrate/translator.py
