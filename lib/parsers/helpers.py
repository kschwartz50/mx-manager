"""Shared XML helpers for MX parsers.

Junos XML config dumps frequently contain ``<junos:comment>`` elements using
a namespace prefix that is not declared at the document root. Passing those
bytes straight to ElementTree raises ``unbound prefix`` errors. This module
provides a light sanitizer that either declares the namespace or strips the
offending elements so the rest of the parser can be written with plain
ElementTree queries.
"""

import re
import xml.etree.ElementTree as ET
from typing import Optional


# Matches <junos:xxx .../> (self-closing) and <junos:xxx ...>...</junos:xxx>.
_JUNOS_SELF_CLOSING = re.compile(rb"<junos:[A-Za-z0-9_-]+(\s[^/>]*)?/>", re.DOTALL)
_JUNOS_PAIRED = re.compile(
    rb"<junos:([A-Za-z0-9_-]+)(\s[^>]*)?>.*?</junos:\1>", re.DOTALL
)


def sanitize_junos_xml(xml_bytes: bytes) -> bytes:
    """Strip all ``junos:``-namespaced elements that lack a declared namespace.

    Junos XML config dumps routinely contain elements like ``<junos:comment>``
    and ``<junos:group-extent>`` whose namespace prefix is never declared at
    the document root.  Passing those bytes directly to ElementTree raises
    ``xml.etree.ElementTree.ParseError: unbound prefix``.

    This function removes *every* ``junos:``-prefixed element — both
    self-closing (``<junos:foo />``) and paired (``<junos:foo>…</junos:foo>``).
    In practice all such elements are metadata or presentation hints that carry
    no configuration semantics for static analysis.  However the removal is
    intentionally broad: if a future Junos release introduces a meaningful
    ``junos:``-namespaced element, it will be silently discarded here.  If that
    risk materialises, narrow the patterns to the specific tags that cause parse
    errors or switch to declaring the ``junos:`` namespace prefix before
    parsing.
    """
    cleaned = _JUNOS_SELF_CLOSING.sub(b"", xml_bytes)
    cleaned = _JUNOS_PAIRED.sub(b"", cleaned)
    return cleaned


def get_text(parent: ET.Element, tag: str) -> Optional[str]:
    """Return the stripped text of ``parent/tag`` if present, else None."""
    child = parent.find(tag)
    if child is not None and child.text is not None:
        text = child.text.strip()
        return text if text else None
    return None


def get_int(parent: ET.Element, tag: str) -> Optional[int]:
    """Return ``parent/tag`` text parsed as an int, or None."""
    val = get_text(parent, tag)
    if val is None:
        return None
    try:
        return int(val)
    except ValueError:
        return None


def get_raw_xml(elem: ET.Element) -> str:
    """Return a compacted XML string for the element.

    Removes newlines and indentation while preserving spaces within text nodes.
    """
    raw = ET.tostring(elem, encoding="unicode")
    return re.sub(r">\s+<", "><", raw.strip())
