"""Generator ↔ Checker adversarial validation loop.

Based on offensive-claude's pattern:
  1. finding-validator presents the finding with evidence
  2. finding-checker (blind, no operator context) attempts to refute it
  3. Outcomes: ACCEPTED / STALL (needs more evidence) / KILLED
  4. Maximum 3 rounds per finding

The checker never sees the operator's reasoning or the engagement context —
only the finding artifact + evidence. This prevents confirmation bias.
"""

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path


class RebuttalOutcome(str, Enum):
    PENDING = "pending"
    ACCEPTED = "accepted"
    STALL = "stall"
    KILLED = "killed"
    EXHAUSTED = "exhausted"


@dataclass
class RebuttalRound:
    round_number: int
    checker_challenge: str
    validator_response: str
    outcome: str = RebuttalOutcome.PENDING.value
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


@dataclass
class RebuttalSession:
    finding_id: str
    max_rounds: int = 3
    current_round: int = 0
    outcome: str = RebuttalOutcome.PENDING.value
    rounds: list[dict] = field(default_factory=list)
    started_at: str = ""
    completed_at: str = ""

    def __post_init__(self):
        if not self.started_at:
            self.started_at = datetime.now(timezone.utc).isoformat()


CHECKER_PROMPTS = {
    "initial": (
        "You are a skeptical security reviewer. You have NEVER seen this engagement "
        "before. You know NOTHING about the operator's goals, reasoning, or context. "
        "You see ONLY the finding below and its evidence.\n\n"
        "Your job: try to KILL this finding. Find reasons it is wrong, incomplete, "
        "unreproducible, or overstated. Be adversarial.\n\n"
        "If you cannot find a valid reason to kill it after thorough analysis, "
        "say ACCEPTED. If you need more evidence, say STALL and explain what's missing. "
        "If it's invalid, say KILLED and explain why.\n\n"
        "FINDING:\n{finding_json}\n\n"
        "EVIDENCE:\n{evidence_json}"
    ),
    "followup": (
        "The validator responded to your challenge:\n\n"
        "YOUR CHALLENGE: {challenge}\n\n"
        "VALIDATOR RESPONSE: {response}\n\n"
        "Does this address your concern? "
        "ACCEPTED = concern resolved. STALL = still insufficient. KILLED = finding is invalid."
    ),
}

REFUTATION_QUESTIONS = [
    "Is this reproducible by someone with no prior knowledge of the target?",
    "Could an existing security control (WAF, rate limiter, CSRF token) block this?",
    "Does the PoC actually demonstrate the claimed impact, or just a precondition?",
    "Is this a real vulnerability or just an informational observation?",
    "Could this be a false positive from the scanning tool?",
    "Is the severity overstated relative to what was actually demonstrated?",
    "Would a reasonable attacker actually exploit this, or is it theoretical?",
    "Is the vulnerable endpoint reachable from an external/unprivileged position?",
    "Are there deployment assumptions that might not hold in production?",
    "Has deduplication been checked — is this the same root cause as another finding?",
]


class RebuttalEngine:
    def __init__(self, audit_dir: str):
        self.state_dir = Path(audit_dir) / ".pentest-state"
        self.rebuttal_file = self.state_dir / "rebuttals.json"
        self._sessions: dict[str, RebuttalSession] = {}
        self._load()

    def _load(self):
        if self.rebuttal_file.exists():
            data = json.loads(self.rebuttal_file.read_text())
            for sd in data.get("sessions", []):
                s = RebuttalSession(**sd)
                self._sessions[s.finding_id] = s

    def _save(self):
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.rebuttal_file.write_text(json.dumps({
            "sessions": [asdict(s) for s in self._sessions.values()],
        }, indent=2))

    def start_session(self, finding_id: str, max_rounds: int = 3) -> RebuttalSession:
        session = RebuttalSession(finding_id=finding_id, max_rounds=max_rounds)
        self._sessions[finding_id] = session
        self._save()
        return session

    def get_checker_prompt(self, finding_id: str, finding_data: dict, evidence_data: list[dict]) -> str | None:
        session = self._sessions.get(finding_id)
        if not session or session.outcome != RebuttalOutcome.PENDING.value:
            return None

        if session.current_round == 0:
            return CHECKER_PROMPTS["initial"].format(
                finding_json=json.dumps(finding_data, indent=2),
                evidence_json=json.dumps(evidence_data, indent=2),
            )

        last_round = session.rounds[-1] if session.rounds else None
        if last_round and last_round.get("outcome") == RebuttalOutcome.STALL.value:
            return CHECKER_PROMPTS["followup"].format(
                challenge=last_round["checker_challenge"],
                response=last_round["validator_response"],
            )
        return None

    def record_round(
        self,
        finding_id: str,
        checker_challenge: str,
        validator_response: str,
        outcome: RebuttalOutcome,
    ) -> RebuttalSession | None:
        session = self._sessions.get(finding_id)
        if not session:
            return None

        session.current_round += 1
        round_data = RebuttalRound(
            round_number=session.current_round,
            checker_challenge=checker_challenge,
            validator_response=validator_response,
            outcome=outcome.value,
        )
        session.rounds.append(asdict(round_data))

        if outcome in (RebuttalOutcome.ACCEPTED, RebuttalOutcome.KILLED):
            session.outcome = outcome.value
            session.completed_at = datetime.now(timezone.utc).isoformat()
        elif session.current_round >= session.max_rounds:
            session.outcome = RebuttalOutcome.EXHAUSTED.value
            session.completed_at = datetime.now(timezone.utc).isoformat()

        self._save()
        return session

    def get_session(self, finding_id: str) -> RebuttalSession | None:
        return self._sessions.get(finding_id)

    def pending_sessions(self) -> list[RebuttalSession]:
        return [s for s in self._sessions.values() if s.outcome == RebuttalOutcome.PENDING.value]

    def start_re_exploit(self, finding_id: str, finding_data: dict) -> str:
        """Generate a blind re-exploitation prompt.

        A fresh agent receives ONLY the vulnerability class, target asset,
        and affected parameter — no PoC, no payloads, no operator reasoning.
        If the blind agent independently reproduces the finding, confidence
        is CONFIRMED. If not, the finding gets STALL or KILLED.
        """
        return (
            "You are a penetration tester verifying a reported vulnerability. "
            "You have NEVER seen this engagement before. You know NOTHING about "
            "prior findings or the operator's work.\n\n"
            "TASK: Independently confirm or deny the following vulnerability.\n\n"
            f"Target: {finding_data.get('target_asset', 'unknown')}\n"
            f"Vulnerability class: {finding_data.get('vuln_class', 'unknown')}\n"
            f"Affected parameter/endpoint: {finding_data.get('description', 'unknown')[:200]}\n\n"
            "You must:\n"
            "1. Craft your OWN payloads (do not ask for the original PoC)\n"
            "2. Test against the target independently\n"
            "3. Report: CONFIRMED (with your own PoC) or DENIED (with evidence "
            "of why it doesn't work)\n\n"
            "Do NOT assume the original finding is correct. Be skeptical."
        )

    def summary(self) -> dict:
        by_outcome = {}
        for s in self._sessions.values():
            by_outcome[s.outcome] = by_outcome.get(s.outcome, 0) + 1
        return {"total": len(self._sessions), "by_outcome": by_outcome}


@dataclass
class AgentVerdict:
    agent_id: str
    verdict: str  # CONFIRMED / DENIED / UNCERTAIN
    confidence: float
    reasoning: str
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


@dataclass
class ReconciliationSession:
    finding_id: str
    num_agents: int = 3
    verdicts: list[dict] = field(default_factory=list)
    final_verdict: str = "pending"
    final_confidence: float = 0.0
    requires_human: bool = False
    started_at: str = ""
    completed_at: str = ""

    def __post_init__(self):
        if not self.started_at:
            self.started_at = datetime.now(timezone.utc).isoformat()


class ReconciliationEngine:
    """Multi-agent reconciliation for high-stakes findings.

    When a finding is critical (CVSS >= 9.0) or part of a high-value chain,
    run N independent agents and reconcile by majority vote.
    """

    def __init__(self, audit_dir: str):
        self.state_dir = Path(audit_dir) / ".pentest-state"
        self.recon_file = self.state_dir / "reconciliation.json"
        self._sessions: dict[str, ReconciliationSession] = {}
        self._load()

    def _load(self):
        if self.recon_file.exists():
            data = json.loads(self.recon_file.read_text())
            for sd in data.get("sessions", []):
                s = ReconciliationSession(**sd)
                self._sessions[s.finding_id] = s

    def _save(self):
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.recon_file.write_text(json.dumps({
            "sessions": [asdict(s) for s in self._sessions.values()],
        }, indent=2))

    def start_reconciliation(self, finding_id: str, num_agents: int = 3) -> dict:
        session = ReconciliationSession(finding_id=finding_id, num_agents=num_agents)
        self._sessions[finding_id] = session
        self._save()
        return asdict(session)

    def record_agent_verdict(
        self,
        finding_id: str,
        agent_id: str,
        verdict: str,
        confidence: float,
        reasoning: str,
    ) -> dict:
        session = self._sessions.get(finding_id)
        if not session:
            return {"error": "No reconciliation session for this finding"}

        v = AgentVerdict(
            agent_id=agent_id,
            verdict=verdict.upper(),
            confidence=min(1.0, max(0.0, confidence)),
            reasoning=reasoning,
        )
        session.verdicts.append(asdict(v))
        self._save()
        return asdict(v)

    def reconcile(self, finding_id: str) -> dict:
        session = self._sessions.get(finding_id)
        if not session:
            return {"error": "No reconciliation session for this finding"}

        votes = {"CONFIRMED": 0, "DENIED": 0, "UNCERTAIN": 0}
        for v in session.verdicts:
            vd = v.get("verdict", "UNCERTAIN")
            votes[vd] = votes.get(vd, 0) + 1

        total = sum(votes.values())
        if total == 0:
            return {"verdict": "pending", "votes": votes, "requires_human": True}

        majority = max(votes, key=votes.get)
        majority_count = votes[majority]
        confidence = majority_count / total if total > 0 else 0.0

        if majority == "UNCERTAIN" or majority_count <= total / 2:
            final = "SPLIT"
            requires_human = True
        else:
            final = majority
            requires_human = confidence < 0.8

        session.final_verdict = final
        session.final_confidence = confidence
        session.requires_human = requires_human
        session.completed_at = datetime.now(timezone.utc).isoformat()
        self._save()

        return {
            "verdict": final,
            "confidence": round(confidence, 2),
            "votes": votes,
            "requires_human": requires_human,
        }

    def pending_reconciliations(self) -> list[dict]:
        return [
            asdict(s) for s in self._sessions.values()
            if s.final_verdict == "pending"
        ]
