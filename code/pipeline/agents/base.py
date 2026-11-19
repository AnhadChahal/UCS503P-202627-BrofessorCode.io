"""Every agent has the same shape: read the context, return a verdict (FR23)."""

from __future__ import annotations

from abc import ABC, abstractmethod

from pipeline.models import PipelineContext, Verdict


class Agent(ABC):
    name: str = "Agent"

    @abstractmethod
    def run(self, ctx: PipelineContext) -> Verdict:
        """Inspect ctx and return a Verdict. Agents never call each other and never
        write to the database; the orchestrator stores what they return."""
