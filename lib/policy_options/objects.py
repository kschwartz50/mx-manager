"""Dataclass hierarchy for the MX policy-options slice.

Objects cover all global routing policy constructs: prefix-lists, AS-path
regexes, policy-statements, and their constituent terms.

Graph relationships (read-only reference — the factory wires the edges):

    ConfigRoot -> PolicyOptionsRoot                  (label: "policy_options_root")
    PolicyOptionsRoot -> PrefixListContainer         (label: "prefix_list_container")
    PolicyOptionsRoot -> AsPathContainer             (label: "as_path_container")
    PolicyOptionsRoot -> PolicyStatementContainer    (label: "policy_statement_container")
    PrefixListContainer -> PrefixList                (label: "prefix_list")
    AsPathContainer -> AsPath                        (label: "as_path")
    PolicyStatementContainer -> PolicyStatement      (label: "policy_statement")
    PolicyStatement -> PolicyTerm                    (label: "policy_term", order: N)
    PolicyTerm -> PrefixList                         (label: "matches_prefix_list")
    PolicyTerm -> AsPath                             (label: "matches_as_path")
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from lib.registry.objects import BaseNode


@dataclass(kw_only=True)
class PolicyOptionsRoot(BaseNode):
    """Top-level anchor for the policy-options slice.

    Edges: ConfigRoot -> PolicyOptionsRoot (label: "policy_options_root")
    """

    type: str = field(default="PolicyOptionsRoot")


@dataclass(kw_only=True)
class PrefixListContainer(BaseNode):
    """Container holding PrefixList nodes.

    Edges: PolicyOptionsRoot -> PrefixListContainer (label: "prefix_list_container")
    """

    type: str = field(default="PrefixListContainer")


@dataclass(kw_only=True)
class AsPathContainer(BaseNode):
    """Container holding AsPath nodes.

    Edges: PolicyOptionsRoot -> AsPathContainer (label: "as_path_container")
    """

    type: str = field(default="AsPathContainer")


@dataclass(kw_only=True)
class PolicyStatementContainer(BaseNode):
    """Container holding PolicyStatement nodes.

    Edges: PolicyOptionsRoot -> PolicyStatementContainer (label: "policy_statement_container")
    """

    type: str = field(default="PolicyStatementContainer")


@dataclass(kw_only=True)
class PrefixList(BaseNode):
    """Named list of IP prefixes.

    Edges: PrefixListContainer -> PrefixList (label: "prefix_list")
    """

    prefixes: List[str] = field(default_factory=list)
    type: str = field(default="PrefixList")


@dataclass(kw_only=True)
class AsPath(BaseNode):
    """Named AS path regex.

    Edges: AsPathContainer -> AsPath (label: "as_path")
    """

    path: str
    type: str = field(default="AsPath")


@dataclass(kw_only=True)
class PolicyStatement(BaseNode):
    """Named policy-statement container.

    Edges:
        PolicyStatementContainer -> PolicyStatement (label: "policy_statement")
        PolicyStatement -> PolicyTerm (label: "policy_term", order: N)
        BgpGroup -> PolicyStatement   (label: "import_policy" | "export_policy", order: N)
    """

    type: str = field(default="PolicyStatement")


@dataclass(kw_only=True)
class PolicyTerm(BaseNode):
    """Logic unit inside a PolicyStatement.

    Edges:
        PolicyStatement -> PolicyTerm (label: "policy_term", order: N)
        PolicyTerm -> PrefixList (label: "matches_prefix_list")
        PolicyTerm -> AsPath (label: "matches_as_path")
    """

    from_protocols: List[str] = field(default_factory=list)
    route_filters: List[dict] = field(default_factory=list)
    actions: List[str] = field(default_factory=list)
    next_hop: Optional[str] = None
    type: str = field(default="PolicyTerm")


# end of lib/policy_options/objects.py
