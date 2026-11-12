"""Pre-engagement cost estimation.

Estimates tool call budget and token consumption before the engagement
runs, based on target surface area (endpoints, assets, technologies).
Helps operators decide scope and budget before committing resources.
"""

from dataclasses import dataclass, field


COST_PER_UNIT = {
    "recon_passive_per_asset": 15,
    "recon_active_per_asset": 30,
    "recon_per_technology": 5,
    "mapping_per_asset": 10,
    "hunting_per_vuln_class": 8,
    "hunting_per_endpoint": 3,
    "chain_per_finding_pair": 2,
    "validation_per_finding": 5,
    "report_base": 10,
    "report_per_finding": 2,
}

TOKEN_ESTIMATE = {
    "haiku": {"input": 2000, "output": 500},
    "sonnet": {"input": 4000, "output": 1500},
    "opus": {"input": 8000, "output": 3000},
}

PRICE_PER_MTOK = {
    "haiku": {"input": 0.25, "output": 1.25},
    "sonnet": {"input": 3.0, "output": 15.0},
    "opus": {"input": 15.0, "output": 75.0},
}

PHASE_MODEL_MIX = {
    "recon": {"haiku": 0.6, "sonnet": 0.4},
    "mapping": {"haiku": 0.3, "sonnet": 0.7},
    "hunting": {"sonnet": 0.8, "opus": 0.2},
    "chaining": {"sonnet": 0.7, "opus": 0.3},
    "validation": {"sonnet": 0.6, "opus": 0.4},
    "reporting": {"sonnet": 0.9, "opus": 0.1},
}

MODE_VULN_CLASSES = {
    "bounty": 15,
    "pentest": 25,
    "comprehensive": 40,
}


@dataclass
class PhaseEstimate:
    phase: str
    estimated_calls: int
    estimated_input_tokens: int = 0
    estimated_output_tokens: int = 0
    estimated_cost_usd: float = 0.0
    assumptions: list[str] = field(default_factory=list)


@dataclass
class EngagementEstimate:
    total_calls: int = 0
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    estimated_cost_usd: float = 0.0
    by_phase: list[dict] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)
    recommended_budget_multiplier: float = 1.5


class CostEstimator:
    def estimate(
        self,
        num_assets: int = 1,
        num_endpoints: int = 0,
        num_technologies: int = 0,
        num_vuln_classes: int = 0,
        engagement_type: str = "web_app",
        mode: str = "pentest",
    ) -> EngagementEstimate:
        if not num_vuln_classes:
            num_vuln_classes = MODE_VULN_CLASSES.get(mode, 25)
        if not num_endpoints:
            num_endpoints = num_assets * 20

        estimated_findings = max(1, int(num_endpoints * 0.05))

        phases = [
            self._estimate_recon(num_assets, num_technologies),
            self._estimate_mapping(num_assets),
            self._estimate_hunting(num_endpoints, num_vuln_classes, mode),
            self._estimate_chaining(estimated_findings),
            self._estimate_validation(estimated_findings),
            self._estimate_reporting(estimated_findings),
        ]

        total_calls = sum(p.estimated_calls for p in phases)
        total_input = sum(p.estimated_input_tokens for p in phases)
        total_output = sum(p.estimated_output_tokens for p in phases)
        total_cost = sum(p.estimated_cost_usd for p in phases)

        assumptions = [
            f"{num_assets} assets, ~{num_endpoints} endpoints",
            f"{num_vuln_classes} vuln classes ({mode} mode)",
            f"~{estimated_findings} findings estimated (5% of endpoints)",
            "1.5x buffer recommended for unknowns",
        ]

        return EngagementEstimate(
            total_calls=total_calls,
            total_input_tokens=total_input,
            total_output_tokens=total_output,
            estimated_cost_usd=total_cost,
            by_phase=[
                {
                    "phase": p.phase,
                    "calls": p.estimated_calls,
                    "cost_usd": round(p.estimated_cost_usd, 2),
                    "assumptions": p.assumptions,
                }
                for p in phases
            ],
            assumptions=assumptions,
        )

    def _estimate_phase_tokens(self, phase: str, calls: int) -> tuple[int, int, float]:
        mix = PHASE_MODEL_MIX.get(phase, {"sonnet": 1.0})
        total_input = 0
        total_output = 0
        total_cost = 0.0
        for model, fraction in mix.items():
            model_calls = int(calls * fraction)
            inp = model_calls * TOKEN_ESTIMATE[model]["input"]
            out = model_calls * TOKEN_ESTIMATE[model]["output"]
            total_input += inp
            total_output += out
            total_cost += (inp / 1_000_000) * PRICE_PER_MTOK[model]["input"]
            total_cost += (out / 1_000_000) * PRICE_PER_MTOK[model]["output"]
        return total_input, total_output, total_cost

    def _estimate_recon(self, num_assets: int, num_technologies: int) -> PhaseEstimate:
        calls = (
            num_assets * COST_PER_UNIT["recon_passive_per_asset"]
            + num_assets * COST_PER_UNIT["recon_active_per_asset"]
            + num_technologies * COST_PER_UNIT["recon_per_technology"]
        )
        inp, out, cost = self._estimate_phase_tokens("recon", calls)
        return PhaseEstimate(
            phase="recon",
            estimated_calls=calls,
            estimated_input_tokens=inp,
            estimated_output_tokens=out,
            estimated_cost_usd=round(cost, 2),
            assumptions=[f"{num_assets} assets × 45 calls + {num_technologies} techs × 5"],
        )

    def _estimate_mapping(self, num_assets: int) -> PhaseEstimate:
        calls = num_assets * COST_PER_UNIT["mapping_per_asset"]
        inp, out, cost = self._estimate_phase_tokens("mapping", calls)
        return PhaseEstimate(
            phase="mapping",
            estimated_calls=calls,
            estimated_input_tokens=inp,
            estimated_output_tokens=out,
            estimated_cost_usd=round(cost, 2),
            assumptions=[f"{num_assets} assets × 10 calls (5 maps)"],
        )

    def _estimate_hunting(self, num_endpoints: int, num_vuln_classes: int, mode: str) -> PhaseEstimate:
        calls = (
            num_vuln_classes * COST_PER_UNIT["hunting_per_vuln_class"]
            + num_endpoints * COST_PER_UNIT["hunting_per_endpoint"]
        )
        inp, out, cost = self._estimate_phase_tokens("hunting", calls)
        return PhaseEstimate(
            phase="hunting",
            estimated_calls=calls,
            estimated_input_tokens=inp,
            estimated_output_tokens=out,
            estimated_cost_usd=round(cost, 2),
            assumptions=[
                f"{num_vuln_classes} classes × 8 + {num_endpoints} endpoints × 3",
                f"Mode: {mode}",
            ],
        )

    def _estimate_chaining(self, estimated_findings: int) -> PhaseEstimate:
        pairs = max(1, estimated_findings * (estimated_findings - 1) // 2)
        calls = min(pairs, 50) * COST_PER_UNIT["chain_per_finding_pair"]
        inp, out, cost = self._estimate_phase_tokens("chaining", calls)
        return PhaseEstimate(
            phase="chaining",
            estimated_calls=calls,
            estimated_input_tokens=inp,
            estimated_output_tokens=out,
            estimated_cost_usd=round(cost, 2),
            assumptions=[f"{estimated_findings} findings → {min(pairs, 50)} pairs × 2 calls"],
        )

    def _estimate_validation(self, estimated_findings: int) -> PhaseEstimate:
        calls = estimated_findings * COST_PER_UNIT["validation_per_finding"]
        inp, out, cost = self._estimate_phase_tokens("validation", calls)
        return PhaseEstimate(
            phase="validation",
            estimated_calls=calls,
            estimated_input_tokens=inp,
            estimated_output_tokens=out,
            estimated_cost_usd=round(cost, 2),
            assumptions=[f"{estimated_findings} findings × 5 calls (4-gate + rebuttal)"],
        )

    def _estimate_reporting(self, estimated_findings: int) -> PhaseEstimate:
        calls = COST_PER_UNIT["report_base"] + estimated_findings * COST_PER_UNIT["report_per_finding"]
        inp, out, cost = self._estimate_phase_tokens("reporting", calls)
        return PhaseEstimate(
            phase="reporting",
            estimated_calls=calls,
            estimated_input_tokens=inp,
            estimated_output_tokens=out,
            estimated_cost_usd=round(cost, 2),
            assumptions=[f"10 base + {estimated_findings} findings × 2"],
        )

    def format_summary(self, est: EngagementEstimate) -> str:
        lines = [
            "## Pre-Engagement Cost Estimate",
            "",
            f"**Total tool calls:** ~{est.total_calls}",
            f"**Total tokens:** ~{est.total_input_tokens + est.total_output_tokens:,}",
            f"**Estimated cost:** ~${est.estimated_cost_usd:.2f}",
            f"**Recommended budget (×{est.recommended_budget_multiplier}):** "
            f"~${est.estimated_cost_usd * est.recommended_budget_multiplier:.2f}",
            "",
            "### By Phase",
            "",
            "| Phase | Calls | Cost | Notes |",
            "|-------|-------|------|-------|",
        ]
        for p in est.by_phase:
            notes = "; ".join(p["assumptions"])
            lines.append(f"| {p['phase']} | {p['calls']} | ${p['cost_usd']:.2f} | {notes} |")
        lines.extend(["", "### Assumptions", ""])
        for a in est.assumptions:
            lines.append(f"- {a}")
        return "\n".join(lines)
