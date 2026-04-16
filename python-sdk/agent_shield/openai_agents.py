"""Agent Shield + OpenAI Agents SDK (openai-agents) integration.

The OpenAI Agents SDK for Python (April 2026 release) ships a Guardrail
primitive for validating inputs, outputs, and tool calls. Agent Shield
plugs in natively.

Install both SDKs:
    pip install openai-agents agent-shield

Usage:
    from agents import Agent, Runner
    from agent_shield.openai_agents import shield_openai_agent

    guardrails = shield_openai_agent(block_on_threat=True, sensitivity='high')

    agent = Agent(
        name='Assistant',
        instructions='You are a helpful assistant',
        input_guardrails=[guardrails['input_guardrail']],
        output_guardrails=[guardrails['output_guardrail']],
    )

    result = Runner.run_sync(agent, user_input)
"""
from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Optional

from .shield import AgentShield


_SEVERITY_RANK = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}


def _should_block(max_severity: Optional[str], threshold: str) -> bool:
    if not max_severity:
        return False
    return _SEVERITY_RANK.get(max_severity, 99) <= _SEVERITY_RANK.get(threshold, 99)


def _normalize_agent_input(inp: Any) -> List[str]:
    """Normalize the OpenAI Agents SDK input shape into user-role text strings.

    Handles: string, list of messages, single message with content parts.
    """
    if inp is None:
        return []
    if isinstance(inp, str):
        return [inp]

    texts: List[str] = []

    if isinstance(inp, list):
        for item in inp:
            if isinstance(item, str):
                texts.append(item)
                continue
            role = getattr(item, 'role', None) or (item.get('role') if isinstance(item, dict) else None)
            if role not in ('user', 'system'):
                continue
            content = getattr(item, 'content', None) or (item.get('content') if isinstance(item, dict) else None)
            if isinstance(content, str):
                texts.append(content)
            elif isinstance(content, list):
                for part in content:
                    if isinstance(part, str):
                        texts.append(part)
                    elif isinstance(part, dict):
                        t = part.get('text') or part.get('content')
                        if isinstance(t, str):
                            texts.append(t)
                    else:
                        t = getattr(part, 'text', None)
                        if isinstance(t, str):
                            texts.append(t)
        return texts

    # Single message-like object
    if isinstance(inp, dict):
        content = inp.get('content')
    else:
        content = getattr(inp, 'content', None)

    if isinstance(content, str):
        return [content]
    if isinstance(content, list):
        for p in content:
            if isinstance(p, str):
                texts.append(p)
            elif isinstance(p, dict) and isinstance(p.get('text'), str):
                texts.append(p['text'])
        return texts

    return []


class _GuardrailResult:
    """Mimics the OpenAI Agents SDK GuardrailFunctionOutput shape.

    The real SDK class is ``GuardrailFunctionOutput``. This shim matches the
    expected interface (``output_info`` + ``tripwire_triggered``) without
    requiring openai-agents to be installed at import time.
    """

    __slots__ = ('output_info', 'tripwire_triggered')

    def __init__(self, output_info: Dict[str, Any], tripwire_triggered: bool):
        self.output_info = output_info
        self.tripwire_triggered = tripwire_triggered


class _InputGuardrail:
    """Agent Shield input guardrail for openai-agents."""

    def __init__(self, shield: AgentShield, threshold: str):
        self.name = 'Agent Shield -- Input'
        self._shield = shield
        self._threshold = threshold

    async def __call__(self, context: Any, agent: Any, user_input: Any) -> _GuardrailResult:
        return self._execute(user_input)

    def execute(self, ctx: Any) -> _GuardrailResult:
        """Sync-callable variant for frameworks that dispatch sync."""
        user_input = getattr(ctx, 'input', None)
        if user_input is None and isinstance(ctx, dict):
            user_input = ctx.get('input')
        return self._execute(user_input)

    def _execute(self, user_input: Any) -> _GuardrailResult:
        texts = _normalize_agent_input(user_input)

        all_threats: List[Dict[str, Any]] = []
        max_severity: Optional[str] = None

        for text in texts:
            result = self._shield.scan(text)
            threats = result.get('threats') or []
            if threats:
                all_threats.extend(threats)
                for t in threats:
                    sev = t.get('severity')
                    if sev and (max_severity is None or _SEVERITY_RANK.get(sev, 99) < _SEVERITY_RANK.get(max_severity, 99)):
                        max_severity = sev

        return _GuardrailResult(
            output_info={
                'threats': all_threats,
                'max_severity': max_severity,
                'scanned_by': 'agent-shield',
            },
            tripwire_triggered=_should_block(max_severity, self._threshold),
        )


class _OutputGuardrail:
    """Agent Shield output guardrail for openai-agents."""

    def __init__(self, shield: AgentShield, threshold: str):
        self.name = 'Agent Shield -- Output'
        self._shield = shield
        self._threshold = threshold

    async def __call__(self, context: Any, agent: Any, agent_output: Any) -> _GuardrailResult:
        return self._execute(agent_output)

    def execute(self, ctx: Any) -> _GuardrailResult:
        agent_output = getattr(ctx, 'agent_output', None)
        if agent_output is None and isinstance(ctx, dict):
            agent_output = ctx.get('agent_output') or ctx.get('output')
        return self._execute(agent_output)

    def _execute(self, agent_output: Any) -> _GuardrailResult:
        if agent_output is None:
            text = ''
        elif isinstance(agent_output, str):
            text = agent_output
        else:
            try:
                text = json.dumps(agent_output)
            except Exception:
                text = str(agent_output)

        result = self._shield.scan(text)
        threats = result.get('threats') or []
        max_severity: Optional[str] = None
        for t in threats:
            sev = t.get('severity')
            if sev and (max_severity is None or _SEVERITY_RANK.get(sev, 99) < _SEVERITY_RANK.get(max_severity, 99)):
                max_severity = sev

        return _GuardrailResult(
            output_info={
                'threats': threats,
                'max_severity': max_severity,
                'scanned_by': 'agent-shield',
            },
            tripwire_triggered=_should_block(max_severity, self._threshold),
        )


class _ToolGuardrail:
    """Agent Shield tool guardrail — scans tool arguments before execution."""

    def __init__(self, shield: AgentShield, threshold: str):
        self.name = 'Agent Shield -- Tool'
        self._shield = shield
        self._threshold = threshold

    async def __call__(self, context: Any, tool_name: str, args: Any) -> _GuardrailResult:
        return self._execute(tool_name, args)

    def execute(self, ctx: Any) -> _GuardrailResult:
        tool_name = getattr(ctx, 'tool_name', None) or (ctx.get('tool_name') if isinstance(ctx, dict) else 'unknown')
        args = getattr(ctx, 'args', None) or (ctx.get('args') if isinstance(ctx, dict) else {})
        return self._execute(tool_name, args)

    def _execute(self, tool_name: str, args: Any) -> _GuardrailResult:
        try:
            args_text = args if isinstance(args, str) else json.dumps(args)
        except Exception:
            args_text = str(args)

        result = self._shield.scan(args_text)
        threats = result.get('threats') or []
        max_severity: Optional[str] = None
        for t in threats:
            sev = t.get('severity')
            if sev and (max_severity is None or _SEVERITY_RANK.get(sev, 99) < _SEVERITY_RANK.get(max_severity, 99)):
                max_severity = sev

        return _GuardrailResult(
            output_info={
                'threats': threats,
                'tool_name': tool_name,
                'max_severity': max_severity,
                'scanned_by': 'agent-shield',
            },
            tripwire_triggered=_should_block(max_severity, self._threshold),
        )


def shield_openai_agent(
    sensitivity: str = 'high',
    block_on_threat: bool = True,
    block_threshold: str = 'high',
    on_threat: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> Dict[str, Any]:
    """Create Agent Shield guardrails for the OpenAI Agents SDK (openai-agents).

    Returns a dict with ``input_guardrail``, ``output_guardrail``,
    ``tool_guardrail``, and the underlying ``shield`` instance. Plug the
    guardrails directly into the Agent constructor.

    Example::

        from agents import Agent, Runner
        from agent_shield.openai_agents import shield_openai_agent

        g = shield_openai_agent(block_on_threat=True)

        agent = Agent(
            name='Assistant',
            instructions='You are a helpful assistant',
            input_guardrails=[g['input_guardrail']],
            output_guardrails=[g['output_guardrail']],
        )

        result = Runner.run_sync(agent, 'What is the weather?')
    """
    shield = AgentShield({
        'block_on_threat': block_on_threat,
        'min_severity': 'low' if sensitivity == 'high' else ('medium' if sensitivity == 'medium' else 'high'),
        'on_threat': on_threat,
    })

    return {
        'input_guardrail': _InputGuardrail(shield, block_threshold),
        'output_guardrail': _OutputGuardrail(shield, block_threshold),
        'tool_guardrail': _ToolGuardrail(shield, block_threshold),
        'shield': shield,
    }
