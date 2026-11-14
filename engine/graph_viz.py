"""Graph visualization — Cytoscape.js export for the Engagement Graph.

Converts the in-memory graph to Cytoscape.js elements JSON and generates
a self-contained HTML file with interactive visualization:
  - Color-coded nodes by type
  - Edge styling by confidence level
  - Filter panel: node types, edge types, min confidence
  - Click-to-inspect: node/edge properties in a side panel
  - Layout: Cola.js force-directed (falls back to cose)
  - Specialized views: architecture, trust, identity, attack-paths, coverage
"""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .graph import EngagementGraph, Node, Edge, Subgraph

NODE_COLORS = {
    "asset": "#4A90D9",
    "service": "#7B68EE",
    "endpoint": "#50C878",
    "identity": "#FF8C00",
    "trust_boundary": "#DC143C",
    "finding": "#FF4444",
    "hypothesis": "#FFD700",
    "test_execution": "#20B2AA",
    "evidence": "#87CEEB",
    "capability": "#9370DB",
    "chain": "#FF6347",
}

NODE_SHAPES = {
    "asset": "rectangle",
    "service": "round-rectangle",
    "endpoint": "ellipse",
    "identity": "diamond",
    "trust_boundary": "pentagon",
    "finding": "star",
    "hypothesis": "triangle",
    "test_execution": "hexagon",
    "evidence": "round-tag",
    "capability": "barrel",
    "chain": "vee",
}

CONFIDENCE_STYLES = {
    "demonstrated": {"line_color": "#2ECC40", "width": 3, "style": "solid"},
    "observed": {"line_color": "#0074D9", "width": 2, "style": "solid"},
    "inferred": {"line_color": "#FF851B", "width": 2, "style": "dashed"},
    "hypothesized": {"line_color": "#AAAAAA", "width": 1, "style": "dotted"},
    "disproved": {"line_color": "#FF4136", "width": 1, "style": "dashed"},
}

VIEWS = {
    "all": {"node_types": None, "edge_types": None},
    "architecture": {
        "node_types": ["asset", "service", "endpoint", "trust_boundary"],
        "edge_types": ["hosts", "exposes", "calls", "trusts", "protects", "crosses"],
    },
    "trust": {
        "node_types": ["identity", "trust_boundary", "service", "capability"],
        "edge_types": ["authenticates_to", "crosses", "grants", "trusts", "protects"],
    },
    "identity": {
        "node_types": ["identity", "service", "endpoint", "capability"],
        "edge_types": ["authenticates_to", "grants", "enables", "scoped_to"],
    },
    "attack_paths": {
        "node_types": ["finding", "chain", "capability", "endpoint", "evidence"],
        "edge_types": ["chains_to", "enables", "grants", "supports", "weakens"],
    },
    "coverage": {
        "node_types": ["endpoint", "test_execution", "hypothesis"],
        "edge_types": ["tested_by", "supports", "refutes", "involves", "derived_from"],
    },
    "evidence": {
        "node_types": ["finding", "evidence", "test_execution", "hypothesis"],
        "edge_types": ["supports", "refutes", "produced", "derived_from"],
    },
}


def to_cytoscape_elements(graph: EngagementGraph,
                          node_types: list[str] | None = None,
                          edge_types: list[str] | None = None,
                          min_confidence: str = "hypothesized") -> list[dict]:
    from .graph import _CONF_ORDER
    min_idx = _CONF_ORDER.get(min_confidence, 0)

    node_ids: set[str] = set()
    elements: list[dict] = []

    for node in graph._nodes.values():
        if node_types and node.type not in node_types:
            continue
        node_ids.add(node.id)
        props = dict(node.properties)
        props.update({
            "label": node.label,
            "node_type": node.type,
            "created_at": node.created_at,
            "source": node.source,
        })
        elements.append({
            "group": "nodes",
            "data": {"id": node.id, **props},
            "classes": node.type,
        })

    for edge in graph._edges.values():
        if _CONF_ORDER.get(edge.confidence, 0) < min_idx:
            continue
        if edge_types and edge.type not in edge_types:
            continue
        if edge.source_id not in node_ids or edge.target_id not in node_ids:
            continue
        props = dict(edge.properties)
        props.update({
            "edge_type": edge.type,
            "confidence": edge.confidence,
            "source": edge.source_id,
            "target": edge.target_id,
            "label": edge.type,
        })
        elements.append({
            "group": "edges",
            "data": {"id": edge.id, **props},
            "classes": f"{edge.type} {edge.confidence}",
        })

    return elements


def to_cytoscape_json(graph: EngagementGraph,
                      view: str = "all",
                      min_confidence: str = "hypothesized",
                      path: str | None = None) -> str:
    view_cfg = VIEWS.get(view, VIEWS["all"])
    elements = to_cytoscape_elements(
        graph,
        node_types=view_cfg["node_types"],
        edge_types=view_cfg["edge_types"],
        min_confidence=min_confidence,
    )
    text = json.dumps(elements, indent=2, ensure_ascii=False)
    if path:
        from pathlib import Path as P
        P(path).write_text(text)
    return text


def generate_html(graph: EngagementGraph,
                  view: str = "all",
                  min_confidence: str = "hypothesized",
                  title: str = "Engagement Graph",
                  path: str | None = None) -> str:
    elements = to_cytoscape_elements(
        graph,
        node_types=VIEWS.get(view, VIEWS["all"])["node_types"],
        edge_types=VIEWS.get(view, VIEWS["all"])["edge_types"],
        min_confidence=min_confidence,
    )
    elements_json = json.dumps(elements, ensure_ascii=False)
    summary = graph.summary()

    node_style_rules = ""
    for ntype, color in NODE_COLORS.items():
        shape = NODE_SHAPES.get(ntype, "ellipse")
        node_style_rules += f"""
      {{
        selector: 'node.{ntype}',
        style: {{
          'background-color': '{color}',
          'shape': '{shape}',
        }}
      }},"""

    conf_style_rules = ""
    for conf, style in CONFIDENCE_STYLES.items():
        conf_style_rules += f"""
      {{
        selector: 'edge.{conf}',
        style: {{
          'line-color': '{style["line_color"]}',
          'target-arrow-color': '{style["line_color"]}',
          'width': {style["width"]},
          'line-style': '{style["style"]}',
        }}
      }},"""

    node_colors_json = json.dumps(NODE_COLORS, ensure_ascii=False)
    views_json = json.dumps(VIEWS, ensure_ascii=False)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_escape(title)}</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.28.1/cytoscape.min.js"></script>
<style>
  :root {{
    --bg: #1a1a2e;
    --panel-bg: #16213e;
    --text: #e0e0e0;
    --text-muted: #8899aa;
    --border: #2a3a5e;
    --accent: #4A90D9;
    --hover: #2a3a5e;
  }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace;
    background: var(--bg);
    color: var(--text);
    display: flex;
    height: 100vh;
    overflow: hidden;
  }}
  #sidebar {{
    width: 280px;
    min-width: 280px;
    background: var(--panel-bg);
    border-right: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    overflow-y: auto;
    padding: 12px;
    gap: 12px;
  }}
  #sidebar h2 {{
    font-size: 14px;
    color: var(--accent);
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-bottom: 4px;
  }}
  #sidebar h3 {{
    font-size: 12px;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin: 8px 0 4px;
  }}
  .stats {{
    font-size: 12px;
    color: var(--text-muted);
    line-height: 1.6;
  }}
  .filter-group {{
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
  }}
  .filter-btn {{
    font-size: 11px;
    padding: 3px 8px;
    border: 1px solid var(--border);
    border-radius: 4px;
    background: transparent;
    color: var(--text);
    cursor: pointer;
    transition: all 0.15s;
  }}
  .filter-btn:hover {{ background: var(--hover); }}
  .filter-btn.active {{
    border-color: var(--accent);
    background: rgba(74, 144, 217, 0.15);
    color: #fff;
  }}
  .view-btn {{
    font-size: 11px;
    padding: 4px 10px;
    border: 1px solid var(--border);
    border-radius: 4px;
    background: transparent;
    color: var(--text);
    cursor: pointer;
    transition: all 0.15s;
  }}
  .view-btn:hover {{ background: var(--hover); }}
  .view-btn.active {{
    border-color: var(--accent);
    background: var(--accent);
    color: #fff;
  }}
  #cy {{
    flex: 1;
    background: var(--bg);
  }}
  #inspector {{
    width: 320px;
    min-width: 320px;
    background: var(--panel-bg);
    border-left: 1px solid var(--border);
    overflow-y: auto;
    padding: 12px;
    display: none;
  }}
  #inspector.open {{ display: block; }}
  #inspector h2 {{
    font-size: 14px;
    color: var(--accent);
    margin-bottom: 8px;
  }}
  .prop-table {{
    width: 100%;
    font-size: 12px;
    border-collapse: collapse;
  }}
  .prop-table td {{
    padding: 3px 6px;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
    word-break: break-word;
  }}
  .prop-table td:first-child {{
    color: var(--text-muted);
    white-space: nowrap;
    width: 100px;
  }}
  .legend {{
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
  }}
  .legend-item {{
    display: flex;
    align-items: center;
    gap: 4px;
    font-size: 11px;
  }}
  .legend-dot {{
    width: 10px;
    height: 10px;
    border-radius: 2px;
    flex-shrink: 0;
  }}
  #close-inspector {{
    float: right;
    background: none;
    border: none;
    color: var(--text-muted);
    cursor: pointer;
    font-size: 16px;
  }}
</style>
</head>
<body>

<div id="sidebar">
  <div>
    <h2>{_escape(title)}</h2>
    <div class="stats" id="stats">
      {summary['node_count']} nodes &middot; {summary['edge_count']} edges
    </div>
  </div>

  <div>
    <h3>Views</h3>
    <div class="filter-group" id="view-group"></div>
  </div>

  <div>
    <h3>Node types</h3>
    <div class="filter-group" id="node-filter"></div>
  </div>

  <div>
    <h3>Min confidence</h3>
    <div class="filter-group" id="conf-filter"></div>
  </div>

  <div>
    <h3>Legend</h3>
    <div class="legend" id="legend"></div>
  </div>
</div>

<div id="cy"></div>

<div id="inspector">
  <button id="close-inspector">&times;</button>
  <h2 id="inspector-title">Inspector</h2>
  <table class="prop-table" id="inspector-table"></table>
</div>

<script>
const ALL_ELEMENTS = {elements_json};
const NODE_COLORS = {node_colors_json};
const VIEWS = {views_json};
const CONFIDENCE_ORDER = ['hypothesized', 'inferred', 'observed', 'demonstrated', 'disproved'];

let cy;
let activeView = 'all';
let activeNodeTypes = new Set(Object.keys(NODE_COLORS));
let minConfidence = 'hypothesized';

function initCy(elements) {{
  cy = cytoscape({{
    container: document.getElementById('cy'),
    elements: elements,
    style: [
      {{
        selector: 'node',
        style: {{
          'label': 'data(label)',
          'font-size': 10,
          'color': '#e0e0e0',
          'text-outline-color': '#1a1a2e',
          'text-outline-width': 1,
          'text-valign': 'bottom',
          'text-margin-y': 4,
          'width': 28,
          'height': 28,
          'border-width': 1,
          'border-color': '#2a3a5e',
        }}
      }},
      {node_style_rules}
      {{
        selector: 'edge',
        style: {{
          'curve-style': 'bezier',
          'target-arrow-shape': 'triangle',
          'arrow-scale': 0.8,
          'label': 'data(label)',
          'font-size': 8,
          'color': '#8899aa',
          'text-rotation': 'autorotate',
          'text-outline-color': '#1a1a2e',
          'text-outline-width': 1,
        }}
      }},
      {conf_style_rules}
      {{
        selector: 'node:selected',
        style: {{
          'border-width': 3,
          'border-color': '#FFD700',
        }}
      }},
      {{
        selector: 'edge:selected',
        style: {{
          'width': 4,
          'line-color': '#FFD700',
          'target-arrow-color': '#FFD700',
        }}
      }},
    ],
    layout: {{
      name: 'cose',
      animate: false,
      nodeDimensionsIncludeLabels: true,
      idealEdgeLength: 80,
      nodeRepulsion: 8000,
      gravity: 0.25,
    }},
    wheelSensitivity: 0.3,
  }});

  cy.on('tap', 'node', function(evt) {{
    showInspector(evt.target.data(), 'node');
  }});
  cy.on('tap', 'edge', function(evt) {{
    showInspector(evt.target.data(), 'edge');
  }});
  cy.on('tap', function(evt) {{
    if (evt.target === cy) closeInspector();
  }});
}}

function filterElements() {{
  const confIdx = CONFIDENCE_ORDER.indexOf(minConfidence);
  const viewCfg = VIEWS[activeView] || VIEWS['all'];
  const viewNodeTypes = viewCfg.node_types ? new Set(viewCfg.node_types) : null;
  const viewEdgeTypes = viewCfg.edge_types ? new Set(viewCfg.edge_types) : null;

  const nodeIds = new Set();
  const filtered = [];

  for (const el of ALL_ELEMENTS) {{
    if (el.group === 'nodes') {{
      const nt = el.data.node_type;
      if (!activeNodeTypes.has(nt)) continue;
      if (viewNodeTypes && !viewNodeTypes.has(nt)) continue;
      nodeIds.add(el.data.id);
      filtered.push(el);
    }}
  }}

  for (const el of ALL_ELEMENTS) {{
    if (el.group === 'edges') {{
      const ec = el.data.confidence;
      const ci = CONFIDENCE_ORDER.indexOf(ec);
      if (ci < confIdx && ec !== 'disproved') continue;
      if (viewEdgeTypes && !viewEdgeTypes.has(el.data.edge_type)) continue;
      if (!nodeIds.has(el.data.source) || !nodeIds.has(el.data.target)) continue;
      filtered.push(el);
    }}
  }}

  return filtered;
}}

function rebuild() {{
  const elements = filterElements();
  cy.elements().remove();
  cy.add(elements);
  cy.layout({{
    name: 'cose',
    animate: false,
    nodeDimensionsIncludeLabels: true,
    idealEdgeLength: 80,
    nodeRepulsion: 8000,
    gravity: 0.25,
  }}).run();

  const nc = cy.nodes().length;
  const ec = cy.edges().length;
  document.getElementById('stats').textContent = nc + ' nodes \\u00b7 ' + ec + ' edges';
}}

function showInspector(data, kind) {{
  const panel = document.getElementById('inspector');
  const title = document.getElementById('inspector-title');
  const table = document.getElementById('inspector-table');
  panel.classList.add('open');
  title.textContent = (kind === 'node' ? '\\u26ab ' : '\\u2194 ') + (data.label || data.id);
  table.innerHTML = '';
  const skip = new Set(['id', 'label']);
  for (const [k, v] of Object.entries(data)) {{
    if (skip.has(k)) continue;
    if (v === '' || v === null || v === undefined) continue;
    const val = typeof v === 'object' ? JSON.stringify(v) : String(v);
    const row = table.insertRow();
    row.insertCell().textContent = k;
    row.insertCell().textContent = val;
  }}
}}

function closeInspector() {{
  document.getElementById('inspector').classList.remove('open');
}}

function buildUI() {{
  const vg = document.getElementById('view-group');
  for (const v of Object.keys(VIEWS)) {{
    const btn = document.createElement('button');
    btn.className = 'view-btn' + (v === activeView ? ' active' : '');
    btn.textContent = v.replace('_', ' ');
    btn.onclick = () => {{
      activeView = v;
      vg.querySelectorAll('.view-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      rebuild();
    }};
    vg.appendChild(btn);
  }}

  const nf = document.getElementById('node-filter');
  for (const [nt, color] of Object.entries(NODE_COLORS)) {{
    const btn = document.createElement('button');
    btn.className = 'filter-btn active';
    btn.innerHTML = '<span style="display:inline-block;width:8px;height:8px;border-radius:2px;background:' + color + ';margin-right:4px"></span>' + nt;
    btn.onclick = () => {{
      if (activeNodeTypes.has(nt)) {{
        activeNodeTypes.delete(nt);
        btn.classList.remove('active');
      }} else {{
        activeNodeTypes.add(nt);
        btn.classList.add('active');
      }}
      rebuild();
    }};
    nf.appendChild(btn);
  }}

  const cf = document.getElementById('conf-filter');
  for (const c of CONFIDENCE_ORDER) {{
    if (c === 'disproved') continue;
    const btn = document.createElement('button');
    btn.className = 'filter-btn' + (c === minConfidence ? ' active' : '');
    btn.textContent = c;
    btn.onclick = () => {{
      minConfidence = c;
      cf.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      rebuild();
    }};
    cf.appendChild(btn);
  }}

  const lg = document.getElementById('legend');
  for (const [nt, color] of Object.entries(NODE_COLORS)) {{
    const item = document.createElement('div');
    item.className = 'legend-item';
    item.innerHTML = '<div class="legend-dot" style="background:' + color + '"></div>' + nt;
    lg.appendChild(item);
  }}
}}

document.getElementById('close-inspector').onclick = closeInspector;

initCy(ALL_ELEMENTS);
buildUI();
</script>
</body>
</html>"""

    if path:
        from pathlib import Path as P
        P(path).parent.mkdir(parents=True, exist_ok=True)
        P(path).write_text(html)

    return html


def _escape(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
