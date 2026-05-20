# MX Manager — Data Model Invariants

This document defines the non-negotiable invariants for the MX Manager data
model. All future development must adhere to these rules. When a proposed
change conflicts with an invariant, the change must be rejected or the
invariant must be explicitly revised here with justification.

---

## 1. Foundational Principles

### 1.1 The Graph Is the Only Source of Truth

The `DataRegistry` graph is the canonical representation of all ingested
configuration. Resolvers and exporters must derive exclusively from graph
state. No slice may reconstruct facts from parser-side data, raw XML, or
export-time inference.

### 1.2 Represent What Is, Not What Should Be

The system is audit-first. It must represent the configuration as parsed —
including gaps, invalid references, and inconsistencies — rather than
correcting or normalizing them. Accuracy takes priority over completeness.
Clean output takes priority over nothing, but never over accurate output.

### 1.3 Explicit Failure Over Silent Correction

Unresolved references must emit a logged warning and remain unresolved in the
graph. They must never be silently corrected, defaulted, or inferred into
validity. Every warning is an auditable signal about the source configuration.

---

## 2. Registry and Graph Invariants

### 2.1 Registry Idempotency

`DataRegistry.register_node(node, unique_key)` is idempotent. If a node with
the given unique key already exists in the registry index, the existing UID is
returned and the new node object is discarded. No duplicate nodes may exist for
the same unique key.

### 2.2 Unique Key Format

Every node registered with the registry must use a deterministic unique key
following the pattern:

```
type-slug|qualifier=value[|qualifier=value…]
```

Established key formats — do not deviate from these without updating this
document:

| Node type | Unique key format |
|---|---|
| `ConfigRoot` | `config-root\|sha256={sha256}` |
| `PolicyOptionsRoot` | `policy-options-root\|root={config_root_uid}` |
| `PrefixListContainer` | `policy-options-prefix-container\|root={config_root_uid}` |
| `AsPathContainer` | `policy-options-as-path-container\|root={config_root_uid}` |
| `PolicyStatementContainer` | `policy-options-policy-container\|root={config_root_uid}` |
| `PrefixList` | `prefix-list\|name={name}` |
| `AsPath` | `as-path\|name={name}` |
| `PolicyStatement` | `policy\|name={name}` |
| `PolicyTerm` | `term\|ps={ps_uid}\|name={name}` |
| `RoutingInstance` | `routing-instance\|name={name}` |
| `StaticRoute` | `static-route\|ri={ri_uid}\|dest={destination}` |
| `BgpGroup` | `bgp-group\|ri={ri_uid}\|name={name}` |
| `BgpNeighbor` | `bgp-neighbor\|group={group_uid}\|ip={peer_address}` |
| `BaseInterfaceNode` | `interface\|name={name}` |
| `UnitInterface` | `interface-unit\|name={name}` |
| `ProtocolsPortsRoot` | `protocols-ports-root\|root={config_root_uid}` |
| `PortListContainer` | `port-list-container\|root={config_root_uid}` |
| `ProtocolAliasContainer` | `protocol-alias-container\|root={config_root_uid}` |
| `PortAliasContainer` | `port-alias-container\|root={config_root_uid}` |
| `PortList` | `port-list\|name={name}` |
| `FirewallRoot` | `firewall-root\|root={config_root_uid}` |
| `FirewallFilterContainer` | `firewall-filter-container\|root={config_root_uid}` |
| `FirewallFilter` | `firewall-filter\|af={address_family}\|name={name}` |
| `FirewallTerm` | `firewall-term\|filter={filter_uid}\|name={name}` |

Container-scoped keys (e.g. `StaticRoute`, `BgpGroup`) intentionally include
the parent UID so the same name can exist under multiple routing instances.
Global-scoped keys (e.g. `PrefixList`, `PolicyStatement`) are intentionally
flat because these objects are global across the config.

### 2.3 `type` Field Is the Registry Bucket Key

Every domain node's `type` field is its registry bucket. It must exactly match
the class name (e.g. `PolicyStatement`, `RoutingInstance`). The `type` field
must never be overridden to a different class name.

### 2.4 `ConfigRoot` Anchors Every Sub-Graph

Every slice's top-level container must be reachable from `ConfigRoot` via a
direct labeled edge. All other nodes in the slice are transitively reachable
through that container. Orphaned nodes — nodes with no path from `ConfigRoot`
— are a bug.

### 2.5 Bidirectional Edge Integrity

`GraphController` maintains `forward_map` and `reverse_map` symmetrically.
All edge creation goes through `add_relationship()`. Never mutate
`forward_map` or `reverse_map` directly.

### 2.6 `raw_config` Preservation

Every node that maps directly to a parsed XML stanza must populate `raw_config`
with the source XML fragment. This is the ground-truth audit trail. It must
never be cleared, overwritten with inferred content, or set to a non-source
value during export.

---

## 3. Ingestion Order Invariant

The importer must ingest slices in this exact order:

1. `ConfigRoot` registration
2. Version detection and parser instantiation
3. **Interfaces** — must precede routing so `RoutingInstanceFactory` can resolve
   `UnitInterface` UIDs by name
4. **Policy options** — must precede routing instances so `RoutingInstanceFactory`
   can resolve `PolicyStatement` UIDs when wiring BGP import/export policies,
   avoiding forward-reference placeholder creation; also must precede firewall
   so `PrefixList` UIDs are registered before firewall cross-slice edges are wired
5. **Protocols / ports** — must precede firewall so `PortList` UIDs are registered
   before the firewall factory wires port-list cross-slice edges
6. **Firewall filters** — after policy-options (PrefixList UIDs) and
   protocols-ports (PortList UIDs); routing has no dependency on firewall
7. **Routing instances**

This order is an architectural contract. New slices must be inserted at the
appropriate position and this document updated.

---

## 4. Parser and Factory Boundary

### 4.1 TypedDict Is the Contract

Parsers communicate with factories exclusively through the TypedDict shapes
defined in `lib/parsers/base.py`. Factories must not import from parser
modules. Parsers must not import from factory or object modules. The TypedDict
boundary is the seam between parsing and graph construction.

### 4.2 Parser Version Bucketing

Parser selection is driven by `MXImporter._parser_map`. The key is a major
version bucket string (e.g. `"21.x"`). Configs with unrecognized version
strings fall back to `"21.x"` with a logged warning. New Junos grammar
variants must be added by registering a new bucket, not by modifying the
existing `MXParser21x`.

### 4.3 No Domain Objects in Parsers

Parser classes must operate on raw `xml.etree.ElementTree` structures and emit
TypedDicts. They must not instantiate domain dataclasses (`BaseNode`
subclasses) or interact with the `DataRegistry`.

---

## 5. Slice Architecture Invariants

### 5.1 Slice Boundaries

Each slice owns its objects, factory, and resolver. The current slices are:

- `lib/interface/` — interfaces and units
- `lib/routing/` — routing instances, static routes, BGP groups and neighbors
- `lib/policy_options/` — prefix-lists, AS-paths, policy-statements and terms

Cross-slice references must be implemented as labeled graph edges, never as
embedded object references or direct imports of another slice's data
structures.

**Controlled exception:** `lib/routing/factory.py` and
`lib/routing/resolvers.py` import `PolicyStatement` from
`lib.policy_options.objects`. This is the single permitted cross-slice object
import, required because BGP groups wire `import_policy` / `export_policy`
edges to `PolicyStatement` nodes. New cross-slice imports require explicit
justification.

### 5.2 Slice Container Structure

Every slice must introduce exactly one top-level container node anchored to
`ConfigRoot`. Internal sub-containers are permitted and must follow the same
graph edge convention. New slices must follow this pattern:

```
ConfigRoot
  └─[<slice_label>]─> <SliceRootContainer>
        └─[<sub_label>]─> <SubContainer>  (if needed)
              └─[<item_label>]─> <LeafNode>
```

### 5.3 Ordered Constructs

Sequences where source order carries semantic meaning must preserve that order
via the `order` property on graph edges. Currently ordered:

- `PolicyStatement → PolicyTerm` (term evaluation order)
- `RoutingInstance → StaticRoute` (route preference order)
- `BgpGroup → PolicyStatement` via `import_policy` / `export_policy` edges

Exporters and resolvers must use `_ordered_edge_uids()` to retrieve these, not
unordered set-based traversal.

---

## 6. Interface Slice Invariants

### 6.1 Distinct Node Types

`BaseInterfaceNode` and `UnitInterface` are distinct node types. A unit is
only created when explicitly present in the XML (`<unit><name>X</name></unit>`).
`.0` units must not be assumed or synthesized.

### 6.2 No Implicit Unit Creation

If a unit is not defined in the source XML it does not exist in the graph.
Routing references to an undefined unit must remain unresolved with a warning.

### 6.3 LAG Membership

Physical interfaces that are members of an aggregate (`ae`) must be represented
as members. They must not be treated as standalone L3 interfaces. References
that target a member interface directly rather than through the aggregate are
invalid and must remain unresolved.

### 6.4 No Base Interface Fallback

Routing resolution must not fall back from `xe-1/0/0.0` to `xe-1/0/0`. Only
exact `UnitInterface` matches are valid.

---

## 7. Protocols-Ports Slice Invariants

### 7.1 Graph Structure

```
ConfigRoot
  └─[protocols_ports_root]─> ProtocolsPortsRoot
        ├─[port_list_container]─> PortListContainer
        │       └─[port_list]─> PortList
        ├─[protocol_alias_container]─> ProtocolAliasContainer  (empty in v1)
        └─[port_alias_container]─> PortAliasContainer          (empty in v1)
```

### 7.2 Only User-Defined Config Objects Become Graph Nodes

`PortList` is the only first-class config object in this slice.  It is
parsed from `<firewall><port-list>` stanzas and registered as a graph node.

Built-in Junos CLI vocabulary — protocol names (`tcp`, `ospf`, `vrrp`),
service port names (`ssh`, `bgp`, `ntp`), and ICMP type/code names — must
**not** be materialized as graph nodes.  They are handled exclusively by
the normalization functions in `helpers.py`.  The `ProtocolAliasContainer`
and `PortAliasContainer` exist for future user-defined aliases only; no
factory code populates them from built-in data.

### 7.3 PortEntry Is a Value Object

`PortEntry` is a frozen dataclass with no graph identity.  It lives as an
element of `PortList.entries`.  Individual port entries must not be
registered with the `DataRegistry`.

### 7.4 Normalization Happens in the Factory, Not the Parser

The parser emits raw port tokens (e.g. `"ssh"`, `"443"`, `"10000-19999"`)
as plain strings.  The factory calls `helpers.normalize_port_token()` to
resolve names to numbers and classify single vs. range entries.  This keeps
the TypedDict boundary clean.

### 7.5 VRRP Protocol Number Is 112

VRRP is IANA protocol 112.  Any helper or migration code that uses 11 for
VRRP is incorrect (11 is NVP-II).  `ProtocolMap` in this codebase uses the
correct IANA value.

### 7.6 Empty Port-List Parser Result Is Valid

Configs that contain no `<firewall><port-list>` stanzas are valid and common.
`parse_port_lists()` must return `[]` in that case.  The factory must still
create the four container nodes so the graph structure is consistent.

---

## 8. Firewall Slice Invariants

### 8.1 Graph Structure

```
ConfigRoot
  └─[firewall_root]─> FirewallRoot
        └─[firewall_filter_container]─> FirewallFilterContainer
                └─[firewall_filter]─> FirewallFilter
                        └─[firewall_term, order=N]─> FirewallTerm
                                ├─[source_prefix_list]──────> PrefixList
                                ├─[destination_prefix_list]─> PrefixList
                                ├─[source_port_list]────────> PortList
                                └─[destination_port_list]───> PortList
```

### 8.2 Address Family Scoping

`FirewallFilter.address_family` must reflect the XML scope of the filter:
- `"inet"` — parsed from `<firewall><family><inet><filter>`
- `"inet6"` — parsed from `<firewall><family><inet6><filter>`
- `"any"` — parsed from top-level `<firewall><filter>` (address-family agnostic)

Filter unique keys include the address family so that same-named filters from
different family scopes do not collide in the registry.

### 8.3 Protocol and Port Conditions Are Normalized Inline

Protocol tokens (`<protocol>`, `<next-header>`) and port tokens (`<port>`,
`<source-port>`, `<destination-port>`) must be normalized using
`helpers.normalize_protocol()` and `helpers.normalize_port_token()` respectively
at factory time. The normalized dicts are stored inline on `FirewallTerm` — not
as separate graph nodes (invariant 7.2). `<next-header>` (the inet6 protocol
match condition) is semantically equivalent to `<protocol>` and is mapped to
the same `protocols` field in the TypedDict.

### 8.4 Cross-Slice References Are Edges, Not Embedded Names

`FirewallTerm` references to `PrefixList` and `PortList` objects must be wired
as labeled graph edges (`source_prefix_list`, `destination_prefix_list`,
`source_port_list`, `destination_port_list`). The raw names must not be stored
on the node — the graph edge is the only record of the reference. Unresolved
references emit a warning and no edge is created; no placeholder nodes may be
created.

### 8.5 Terms Are Ordered

`FirewallFilter → FirewallTerm` edges must carry an `order` property reflecting
the sequence in which terms appear in the source XML. Exporters must use
`_ordered_edge_uids()` to retrieve terms, never unordered set-based traversal.

### 8.6 `FirewallRoot` and Container Always Created

The factory always creates `FirewallRoot` and `FirewallFilterContainer` even
when the config defines no filters. This ensures the graph structure is
consistent across configs and downstream resolvers do not need nil-checks at
every level.

---

## 9. Routing Slice Invariants

### 9.1 Routing Slice Owns

- `RoutingInstance`
- `StaticRoute` + `NextHopSpec`
- `BgpGroup`
- `BgpNeighbor`

### 9.2 Routing Slice Does Not Own

Policy objects (`PolicyStatement`, `PolicyTerm`, `PrefixList`, `AsPath`) belong
to the `policy_options` slice. The routing slice may reference them only via
graph edges.

### 9.3 Static Route Scoping

Static route unique keys must include the parent `ri_uid` so the same
destination prefix can exist in multiple routing instances without collision.

### 9.4 BGP Policy Wiring and the Placeholder Exception

`RoutingInstanceFactory._ensure_policy_node()` creates a bare `PolicyStatement`
placeholder if the referenced policy was not found in the registry. This is a
controlled safety net for out-of-order ingestion.

**This mechanism should never fire in normal operation.** The ingestion order
invariant (Section 3) ensures policy options are ingested before routing
instances. If warnings about placeholder creation appear at runtime, the root
cause is a violation of ingestion order, not a reason to rely on the
placeholder path.

Future work: once the ingestion order is fully enforced, consider replacing
this with an explicit error.

---

## 10. Policy Options Slice Invariants

### 10.1 Graph Structure

```
ConfigRoot
  └─[policy_options_root]─> PolicyOptionsRoot
        ├─[prefix_list_container]─> PrefixListContainer
        │       └─[prefix_list]─> PrefixList
        ├─[as_path_container]─> AsPathContainer
        │       └─[as_path]─> AsPath
        └─[policy_statement_container]─> PolicyStatementContainer
                └─[policy_statement]─> PolicyStatement
                        └─[policy_term, order=N]─> PolicyTerm
                                ├─[matches_prefix_list]─> PrefixList
                                └─[matches_as_path]─> AsPath
```

### 10.2 Prefix-Lists and AS-Paths Are Separate Containers

`PrefixList` nodes live under `PrefixListContainer`. `AsPath` nodes live under
`AsPathContainer`. They must not be mixed into the same container.

### 10.3 Policy-Scoped Keys for Terms

`PolicyTerm` unique keys must include the parent `ps_uid` because term names
are only unique within their policy statement, not globally.

### 10.4 Missing Match References

If a `PolicyTerm` references a `PrefixList` or `AsPath` by name that does not
exist in the registry, a warning must be emitted and the edge must not be
created. No placeholder match objects may be created.

---

## 11. Resolver Discipline

### 11.1 Tier 1 Resolvers (Slice Resolvers)

Slice resolvers (`InterfaceResolver`, `RoutingInstanceResolver`,
`PolicyOptionsResolver`) must be:

- **Intra-slice only** — no imports of objects or factories from other slices
  (except the single documented exception in Section 5.1)
- **UID-based** — all inputs and outputs are UIDs or hydrated dicts; never raw
  node objects
- **Read-only** — resolvers must not mutate the graph or registry
- **Honest** — hydration methods must reflect node state exactly; no derived
  or inferred fields

### 11.2 Context Builders (Export Layer)

Context builders in `lib/exporter.py` (`InterfaceContextBuilder`,
`RoutingContextBuilder`, `PolicyOptionsContextBuilder`) may compose cross-slice
views by calling multiple Tier 1 resolvers. They must not:

- Mutate the graph or registry
- Infer or synthesize data absent from the graph
- Create objects or edges

### 11.3 One Builder Per Slice

Each slice should have exactly one context builder. Builders must not be merged
or share resolver state across slices.

---

## 12. Export Invariants

### 12.1 JSON Reflects Graph Truth

The JSON export must be a faithful projection of graph state. Invalid or
unresolved references may be omitted but must never be replaced with synthetic
data.

### 12.2 Excel Derives From JSON, Not the Graph

`ExcelConfigExporter` reads from `JSONConfigExporter.json_payload`. It must
not interact with the `DataRegistry` or graph directly. This keeps the Excel
layer as a pure rendering concern with no access to graph internals.

### 12.3 No Export-Time Inference

Neither the JSON nor Excel exporter may introduce logic that infers, corrects,
or defaults missing configuration. What is absent from the graph is absent from
the export.

### 12.4 Sheet Order Reflects Ingestion Layer

Excel sheets must be ordered to reflect the logical structure of the data
model, not the ingestion order. Current sheet order: BaseInts → UnitInts →
PrefixLists → AsPaths → PolicyStatements → FirewallFilters → RoutingInstances → StaticRoutes.

---

## 13. Domain Object Invariants

### 13.1 `kw_only=True` on All Domain Dataclasses

All `BaseNode` subclasses must use `@dataclass(kw_only=True)`. This prevents
accidental positional construction and makes instantiation explicit and
refactoring-safe.

### 13.2 `type` Field Has a Default Matching the Class Name

Every domain dataclass must declare `type: str = field(default="ClassName")`
where `ClassName` exactly matches the Python class name. This field drives
registry bucketing and JSON type tagging.

### 13.3 `frozen=True` for Value Objects

Pure value objects with no graph identity (currently `NextHopSpec`) must use
`@dataclass(frozen=True)`. They must not be subclasses of `BaseNode` and must
not be registered with the registry.

---

## 14. New Slice Checklist

When adding a new configuration slice:

1. Create `lib/<slice>/` with `__init__.py`, `objects.py`, `factory.py`,
   `resolvers.py`
2. Define a top-level root container node anchored to `ConfigRoot`
3. Register all objects with deterministic unique keys (document them in
   Section 2.2)
4. Define all TypedDicts in `lib/parsers/base.py` and add an `@abstractmethod`
   to `BaseMXParser`
5. Implement the parse method in `MXParser21x`
6. Wire the factory call into `MXImporter.import_xml()` at the correct
   ingestion order position (update Section 3)
7. Add a context builder to `lib/exporter.py`
8. Add Excel sheet writer(s) and wire them in the correct sheet order
9. Emit warnings for all unresolved references; never create placeholder nodes
10. Update this document

---

## Final Principle

> The system must represent what the configuration **is**, not what it
> **should be**. Any deviation from source truth must be explicit, visible,
> and non-destructive.
