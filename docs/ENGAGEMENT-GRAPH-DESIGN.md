# Engagement Graph — Design Document

**Author:** z3ro_m4d
**Date:** 2026-11-14
**Status:** DRAFT — pending operator approval before implementation

---

## 1. Problem Statement

Quarry's five maps (asset, trust, identity, state, capability), Brain, CoverageTracker,
FindingsStore, and ChainEngine model overlapping aspects of the same engagement but store
them in isolated JSON files with no shared references. This creates three problems:

1. **No connected traversal.** You can't walk from an asset through its endpoints, the
   identities that access them, the tests that ran, the evidence they produced, and the
   findings that resulted — without manually correlating 4+ files.

2. **Capabilities without context.** `ENABLES_MAP` and `FINDING_CAPABILITIES` in brain.py
   grant capabilities globally. An SSRF on Service A doesn't automatically give
   `internal_network` access to Service B, but the current model says it does.

3. **Coverage is a status, not a history.** `CoverageEntry` records one status per
   (asset × class × endpoint × identity × technique) cell. If a test ran twice — once
   blocked by tooling, once conclusive — only the last result survives.

The Engagement Graph makes these relationships explicit, queryable, and evidenced.

---

## 2. Core Concept

The Engagement Graph is a typed, directed property graph that unifies all engagement
knowledge. It is NOT a separate system — it's a shared data layer that the existing
modules (Brain, Coverage, Findings, ChainEngine) read from and write to.

### What it replaces vs. what it extends

| Current module | Fate | Relationship to graph |
|---|---|---|
| `brain.json` | **Extends** | Capabilities become edges from findings to graph nodes |
| `coverage.json` | **Extends** | Coverage cells link to test execution nodes |
| `findings.json` | **Extends** | Findings become nodes with edges to evidence + assets |
| `chains.json` | **Extends** | Chains become subgraph views, not independent records |
| `attack-graph.json` | **Replaced by** | Engagement graph IS the attack graph + more |
| 5 Markdown maps | **Become views** | Generated from graph queries, not hand-written |

### Design principles

1. **One graph, many views.** The attack graph, trust map, coverage report are all
   queries over the same graph — not separate data stores.
2. **Evidence on edges, not just nodes.** Every relationship has a confidence level
   and evidence references. "API X calls Service Y" must point to the observation.
3. **Gradual enrichment.** The graph starts sparse (just assets from recon) and gets
   denser as testing proceeds. Missing edges are visible gaps, not hidden unknowns.
4. **No external dependencies.** JSONL + in-memory graph. No Neo4j, no database server.

---

## 3. Node Types

Each node has: `id` (stable UUID), `type`, `label`, `properties: {}`, `created_at`,
`updated_at`, `source` (what created it: "recon", "manual", "agent:<name>").

| Type | Description | Key properties |
|---|---|---|
| `asset` | Domain, IP, mobile app, cloud resource | `kind` (domain/ip/app/bucket/repo), `in_scope: bool` |
| `service` | Running service on an asset | `port`, `protocol`, `tech_stack: []`, `version` |
| `endpoint` | API endpoint / URL path | `method`, `path`, `parameters: []`, `auth_required: bool` |
| `identity` | Test account, role, API key | `auth_type`, `role`, `permissions: []`, `account_id` |
| `trust_boundary` | Authentication/authorization boundary | `mechanism`, `from_zone`, `to_zone`, `validations: []` |
| `finding` | Confirmed vulnerability | `finding_id` (from FindingsStore), `vuln_class`, `severity`, `evidence_tag` |
| `hypothesis` | Unconfirmed suspicion | `description`, `confidence`, `basis`, `status` (active/confirmed/disproved) |
| `test_execution` | One run of a test | `technique`, `tool`, `status` (pass/fail/blocked/inconclusive), `run_id` |
| `evidence` | Artifact proving something | `artifact_id`, `kind` (request/response/screenshot/output), `custody_hash` |
| `capability` | What an attacker can do | `name` (from CAPABILITY_TAXONOMY), `scope` (which service/asset) |
| `chain` | Attack chain linking findings | `chain_id`, `impact`, `demonstrated: bool` |

---

## 4. Edge Types

Each edge has: `id` (UUID), `type`, `source_id`, `target_id`, `properties: {}`,
`confidence`, `evidence_refs: []`, `created_at`, `source`.

### Confidence levels (epistemic states)

| Level | Meaning | Allowed transitions |
|---|---|---|
| `observed` | Seen directly (DNS record, banner, traffic) | → demonstrated, disproved |
| `demonstrated` | Proven by test execution with evidence | (terminal) |
| `inferred` | Deduced from partial evidence | → demonstrated, disproved |
| `hypothesized` | Suspected, not yet tested | → inferred, demonstrated, disproved |
| `disproved` | Tested and found false | (terminal) |

Disproved edges are **not deleted** — they stay in the graph with `disproved` confidence.
This is critical for coverage tracking ("we tested this and it's not true").

### Edge type catalog

| Type | From → To | Example |
|---|---|---|
| `hosts` | asset → service | "fintual.cl hosts GraphQL on :443" |
| `exposes` | service → endpoint | "API v1 exposes GET /api/goals/:id" |
| `authenticates_to` | identity → service | "Account A authenticates to API via cookie" |
| `crosses` | endpoint → trust_boundary | "POST /api/goals crosses auth boundary" |
| `tested_by` | endpoint → test_execution | "GET /api/goals/:id tested by IDOR test #3" |
| `produced` | test_execution → evidence | "Test #3 produced HTTP 404 response" |
| `supports` | evidence → finding | "404 for foreign ID supports IDOR-safe conclusion" |
| `grants` | finding → capability | "F-CORS grants steal_token on REST API scope" |
| `enables` | capability → hypothesis | "steal_token enables CORS round-trip hypothesis" |
| `chains_to` | finding → finding | "F7-BYPASS + F-CORS form chain C-001" |
| `calls` | service → service | "Frontend calls API via /gql/" |
| `trusts` | service → trust_boundary | "API trusts cookie from auth service" |
| `protects` | trust_boundary → service | "Cloudflare protects frontend" |
| `refutes` | test_execution → hypothesis | "Test #5 disproves CSRF hypothesis" |
| `scoped_to` | capability → service | "internal_network scoped to API, not frontend" |

---

## 5. How Existing Modules Change

### 5.1 chain_engine.py

**KNOWN_CHAINS** — keep as hypothesis catalog, but:
- Rename `severity` → `base_severity_hint`
- When a chain matches in `analyze_matrix()`, the created Chain node gets
  `combined_severity` from demonstrated evidence, not from the catalog
- Add `preconditions: []` field to catalog entries

**ENABLES_MAP** — keep as static lookup, but:
- `analyze_capabilities()` creates `grants` edges with `scope` property
  (which service/asset the capability applies to)
- A capability scoped to Service A does NOT automatically enable
  exploitation on Service B
- The static map is the "what's possible" catalog; the graph edges are
  "what's real in this engagement"

**build_pivot_graph()** — replaced by graph query:
```python
def attack_subgraph(self, graph: EngagementGraph) -> Subgraph:
    """Extract the attack-relevant subgraph: findings, capabilities, chains."""
    return graph.query(
        node_types=["finding", "capability", "chain"],
        edge_types=["grants", "enables", "chains_to"],
        min_confidence="inferred",
    )
```

**find_paths()** — reimplemented over the engagement graph with:
- Proper cycle detection (per-path visited set, currently declared but unused)
- Depth limit (default 6)
- Confidence threshold (only traverse edges above a minimum)
- Trust boundary awareness (paths that cross more boundaries score higher)

### 5.2 brain.py

**Capabilities** become `capability` nodes + `grants` edges:
```python
# Before:
brain.add_capability("steal_token", "F-CORS", confidence=0.9)

# After:
graph.add_node(type="capability", label="steal_token",
               properties={"scope": "rest-api-v1"})
graph.add_edge(type="grants", source="F-CORS", target=cap_node_id,
               confidence="demonstrated",
               evidence_refs=["EV-004"])
```

**ExhaustedVector** → `test_execution` node with status="blocked" or status="fail",
plus `tested_by` edge to the endpoint.

**ActiveVector** → `test_execution` node with status="running".

**Hints** — unchanged (orthogonal to graph).

### 5.3 coverage.py

**CoverageEntry** stays as the tracking unit, but gains:
- `test_execution_ids: list[str]` — links to graph nodes
- Multiple test executions per cell (history, not just last result)
- `effective_status` computed from the latest `test_execution` node's status

**Coverage views** become graph queries:
```python
def get_gaps(self, graph: EngagementGraph) -> list:
    """Endpoints with no test_execution edges, or only inconclusive ones."""
    return graph.query_unconnected(
        node_type="endpoint",
        edge_type="tested_by",
        exclude_statuses=["pass", "finding_detected"],
    )
```

### 5.4 findings.py

**Finding** becomes a node in the graph. The `FindingsStore` still manages the
finding lifecycle (detected → validated → reported), but each finding has:
- `grants` edges to capabilities (scoped)
- `supports` edges from evidence
- `tested_by` edges from test executions
- `chains_to` edges to other findings (when part of a chain)

### 5.5 custody.py

Each graph mutation (add_node, add_edge, update_edge confidence) gets a custody
log entry. The custody chain tracks graph evolution, not just evidence creation.

### 5.6 Map generation (commands/map.md)

The 5 maps become queries:
- **Asset map** → `graph.query(node_types=["asset", "service"], edge_types=["hosts"])`
- **Trust map** → `graph.query(node_types=["trust_boundary", "service"], edge_types=["crosses", "trusts", "protects"])`
- **Identity map** → `graph.query(node_types=["identity", "service"], edge_types=["authenticates_to"])`
- **State map** → `graph.query(node_types=["service"], properties={"has_state": True})`
- **Capability map** → `graph.query(node_types=["capability", "finding"], edge_types=["grants"])`

Markdown output is generated from query results. The map files become derived artifacts,
not source of truth.

---

## 6. Data Model — Storage

### Files (inside `.pentest-state/`)

```
.pentest-state/
├── graph/
│   ├── nodes.jsonl          # One JSON object per line, append-only
│   ├── edges.jsonl          # One JSON object per line, append-only
│   └── index.json           # Adjacency index, rebuilt from JSONL
├── hypotheses.json          # NEW: hypothesis journal
├── test-executions.json     # NEW: test execution history
├── brain.json               # Existing: capabilities, exhausted, hints
├── coverage.json            # Existing: coverage cells
├── findings.json            # Existing: finding lifecycle
├── chains.json              # Existing: chain candidates
├── custody.jsonl            # Existing: custody log
└── knowledge.json           # Existing: cross-engagement KB (outside audit_dir)
```

### Why JSONL + index, not a single JSON

- **Append-only writes** — adding a node or edge is one line appended, no rewrite
- **Custody-compatible** — each line can be hashed into the custody chain
- **index.json rebuilt on load** — adjacency lists, type indexes, ID lookups
- **No external dependencies** — stdlib json, no database

### Node schema (one JSONL line)

```json
{
  "id": "N-a1b2c3d4",
  "type": "endpoint",
  "label": "GET /api/goals/:id",
  "properties": {
    "method": "GET",
    "path": "/api/goals/:id",
    "parameters": ["id"],
    "auth_required": true
  },
  "created_at": "2026-11-14T10:00:00Z",
  "updated_at": "2026-11-14T10:00:00Z",
  "source": "recon"
}
```

### Edge schema (one JSONL line)

```json
{
  "id": "E-x1y2z3",
  "type": "tested_by",
  "source_id": "N-a1b2c3d4",
  "target_id": "N-te001",
  "properties": {},
  "confidence": "demonstrated",
  "evidence_refs": ["EV-004", "EV-005"],
  "created_at": "2026-11-14T11:00:00Z",
  "source": "agent:recon-agent"
}
```

### Update semantics

Nodes and edges are **append-only in JSONL** (immutable log). To update a node or
edge, append a new line with the same `id` — the latest line wins when building
the index. The older line stays for audit trail.

---

## 7. EngagementGraph API

```python
class EngagementGraph:
    def __init__(self, audit_dir: str): ...

    # Mutations (each appends to JSONL + custody log)
    def add_node(self, type: str, label: str, properties: dict = {},
                 source: str = "") -> str:  # returns node_id
    def add_edge(self, type: str, source_id: str, target_id: str,
                 confidence: str = "observed", evidence_refs: list[str] = [],
                 properties: dict = {}, source: str = "") -> str:
    def update_confidence(self, edge_id: str, new_confidence: str,
                          evidence_refs: list[str] = [],
                          reason: str = "") -> None:
    def update_node(self, node_id: str, properties: dict) -> None:

    # Queries (read-only, over in-memory index)
    def get_node(self, node_id: str) -> Node | None
    def get_edges(self, node_id: str, direction: str = "both",
                  edge_type: str | None = None) -> list[Edge]
    def query(self, node_types: list[str] | None = None,
              edge_types: list[str] | None = None,
              min_confidence: str = "hypothesized") -> Subgraph
    def find_paths(self, start_id: str, goal_types: list[str],
                   max_depth: int = 6,
                   min_confidence: str = "inferred") -> list[Path]
    def unconnected(self, node_type: str, edge_type: str) -> list[Node]

    # Views (generate Markdown maps from graph)
    def asset_map(self) -> str
    def trust_map(self) -> str
    def identity_map(self) -> str
    def state_map(self) -> str
    def capability_map(self) -> str

    # Stats
    def summary(self) -> dict
```

---

## 8. Hypothesis Journal

Integrated as `hypothesis` nodes in the graph.

```json
{
  "id": "N-h023",
  "type": "hypothesis",
  "label": "Refresh token survives password change",
  "properties": {
    "description": "Old refresh token may remain valid after password change",
    "basis": "JWT tokens are stateless, no revocation list observed",
    "status": "active",
    "priority": "high",
    "next_test": "Issue token, change password, replay token"
  },
  "created_at": "2026-11-14T10:00:00Z",
  "source": "agent:hunt-agent"
}
```

Edges from hypothesis:
- `hypothesized` → inferred/demonstrated: `refutes` or `supports` edge from test_execution
- `involves` → assets, services, identities the hypothesis concerns
- `derived_from` → findings or evidence that originated the hypothesis

Status lifecycle: `active` → `testing` → `confirmed` (becomes finding) | `disproved` | `deferred`

---

## 9. Test Execution Tracking

Each test execution is a node, not a status flag.

```json
{
  "id": "N-te001",
  "type": "test_execution",
  "label": "IDOR test on GET /api/goals/:id",
  "properties": {
    "technique": "sequential-id-enumeration",
    "tool": "manual-devtools",
    "status": "pass",
    "identity_used": "N-id-account-c",
    "duration_ms": 1200,
    "notes": "404 for foreign IDs, ownership enforced"
  },
  "created_at": "2026-11-13T15:30:00Z",
  "source": "agent:recon-agent"
}
```

This means:
- One endpoint can have multiple test_execution nodes (different techniques, identities, dates)
- A test that fails due to tooling is recorded (`status: "tool_error"`)
- A test blocked by missing credentials is recorded (`status: "blocked"`)
- Coverage becomes: "how many distinct test_executions with status=pass|finding_detected
  exist per endpoint" — not "what's the last status of the coverage cell"

---

## 10. Trust Boundaries as First-Class Entities

```json
{
  "id": "N-tb-api-auth",
  "type": "trust_boundary",
  "label": "API Authentication Boundary",
  "properties": {
    "mechanism": "cookie-session",
    "from_zone": "public-internet",
    "to_zone": "authenticated-api",
    "validations": ["session-cookie", "csrf-token"],
    "identity_transported": "user-id-from-session",
    "data_crossing": ["goals", "bank-accounts", "personal-info"]
  }
}
```

Edges:
- service → `crosses` → trust_boundary (this service's endpoints cross this boundary)
- trust_boundary → `protects` → service (this boundary gates access to this service)
- finding → `weakens` → trust_boundary (this finding undermines this boundary)

This directly feeds chain analysis: a chain that crosses more trust boundaries has higher
impact. A finding that weakens a boundary is more valuable than one that doesn't.

---

## 11. Migration Strategy

### Phase 1: Graph Data Model (this phase)

1. Create `engine/graph.py` with `EngagementGraph` class
2. Define node/edge schemas with validation
3. Implement JSONL storage + in-memory index
4. Add custody integration (each mutation → custody entry)
5. **No changes to existing modules yet** — graph runs alongside

### Phase 2: Integration

1. `brain.py` → capabilities write to graph as nodes+edges
2. `coverage.py` → test executions create graph nodes
3. `findings.py` → findings create graph nodes with edges to evidence
4. `chain_engine.py` → chains query the graph instead of building ad-hoc
5. Existing JSON files remain as the authoritative stores; graph is
   built from them on load (dual-write during transition)

### Phase 3: Hypothesis + Test Journal

1. Hypothesis nodes in graph
2. Test execution nodes replace single-status coverage cells
3. `suggest_next_targets()` queries graph gaps
4. Re-hunting becomes: "find endpoints with no test_execution edges"

### Phase 4: Interactive Graph (`/quarry:graph`)

1. Cytoscape.js visualization (local, no external services)
2. Node selection → panel with relationships, evidence, coverage
3. Specialized views: architecture, trust, identity, attack paths, coverage, evidence
4. Filter by confidence level, node type, edge type

### Phase 5: Graph-driven Hunting

1. Agents receive relevant subgraph instead of flat briefing
2. `generate_briefing()` returns graph context around the target
3. Chain suggestions come from graph path analysis
4. Gaps are concrete: "endpoint X has no test_execution with identity Y"

### Phase 6: Independent Verification

1. Finding-checker receives evidence subgraph only (not conclusions)
2. Reproduction runs in isolated session with graph read-only access
3. Verification result creates new test_execution node

---

## 12. What NOT to Change

- **KNOWN_CHAINS table** — keep as hypothesis catalog. Reclassify `severity` as `base_severity_hint`.
- **ENABLES_MAP** — keep as static lookup for possibility space. Graph edges carry the actual context.
- **Custody chain** — extend, don't replace. Graph mutations add entries.
- **Seven Question Gate** — orthogonal to graph. Keep as-is.
- **Anti-fabrication rules** — orthogonal. Keep as-is.
- **knowledge.py** — cross-engagement, lives outside the graph (which is per-engagement).
- **Existing JSON stores** — during transition, they remain source of truth. Graph is built from them.

---

## 13. Acceptance Criteria (Phase 1)

1. `EngagementGraph` loads/saves JSONL with no data loss on round-trip
2. All 10 node types and 15 edge types defined with validation
3. `add_node()`, `add_edge()`, `update_confidence()` append to JSONL and custody
4. `query()` returns correct subgraphs by type and confidence
5. `find_paths()` with cycle detection and depth limit works on a 50-node test graph
6. `unconnected()` identifies endpoints without test_execution edges
7. Existing modules (brain, coverage, findings, chains) are NOT modified
8. Tests: unit tests for graph operations, round-trip serialization, path finding

---

## 14. Decisions for Operator

Before implementation:

1. **Storage location**: `.pentest-state/graph/` (proposed) or separate?
2. **Phase 1 scope**: graph.py only, or also start Phase 2 integration?
3. **Branch strategy**: feature branch `engagement-graph` off main?
4. **Compatibility**: maintain backward compat with existing .pentest-state/ or clean break?

---

## 15. Fintual Engagement as Validation Example

The current Fintual audit (~/Dev/personal/fintual_audit/) would produce:

**Nodes (sample):**
- asset: fintual.cl, fintual.mx, headquarters.fintual.in, link.fintual.com
- service: GraphQL /gql/, REST v1 /api/*, Auth (cookie), Django Admin
- identity: Account A (1201884), Account B (1212081), Account C (1222101)
- trust_boundary: public→auth, auth→KYC, KYC→financial-ops
- finding: F-CORS, F7-BYPASS, V-AUTHZ, F-16, MOB-F1..F10
- hypothesis: CORS round-trip, session fixation via shortlinks, PKCE bypass
- capability: steal_token (scoped to REST v1), forge_request (scoped to REST v1)

**Edges (sample):**
- fintual.cl `hosts` GraphQL (demonstrated)
- REST v1 `exposes` GET /api/goals/:id (demonstrated)
- Account A `authenticates_to` GraphQL (demonstrated)
- GET /api/goals/:id `tested_by` IDOR-test-round-2 (demonstrated, evidence: EV-idor-cross)
- F-CORS `grants` steal_token scoped_to REST v1 (demonstrated)
- F-CORS `weakens` public→auth boundary (inferred — round-trip not yet demonstrated)
- V-AUTHZ `grants` forge_request scoped_to GraphQL mutations (demonstrated)

**Graph-driven gaps that are invisible today:**
- "POST /gql/ mutations: 27 mapped, 11 tested with Account A, 0 tested with Account C"
- "Trust boundary KYC→financial-ops: 0 test executions (blocked: no stocks wallet)"
- "Hypothesis H-CORS-RT: active since Nov 13, 0 test executions (blocked: no password)"

---

## References

- External analysis (Nov 2026) proposing Engagement Knowledge Graph architecture
- TODO-AUDIT.md roadmap items: Hypothesis Journal, Re-hunting, Defense Registry
- IronCurtain (Provos): FSM + journal pattern
- zsec "Bullying LLMs": campaign iteration, episodic memory
- OpenAI "A Thousand Fewer Paths to Root": scout→analyst, abort conditions
