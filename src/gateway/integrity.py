from __future__ import annotations

from gateway.models import ToolDefinition
from gateway.security import stable_hash
from gateway.stores import Repository


def tool_digest(tool: ToolDefinition) -> str:
    return stable_hash(
        {
            "name": tool.name,
            "description": tool.description,
            "inputSchema": tool.inputSchema,
            "outputSchema": tool.outputSchema,
            "annotations": tool.annotations,
        }
    )


class ToolIntegrity:
    def __init__(self, repository: Repository) -> None:
        self.repository = repository

    async def verify_or_enroll(
        self, server_id: str, tool: ToolDefinition, allow_enrollment: bool
    ) -> tuple[bool, str]:
        digest = tool_digest(tool)
        baseline = await self.repository.get_tool_digest(server_id, tool.name)
        if baseline is None and allow_enrollment:
            await self.repository.set_tool_digest(server_id, tool.name, digest)
            return True, digest
        return baseline == digest, digest
