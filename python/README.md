# Agent Shield — Python SDK

Python port of the [Agent Shield](https://github.com/texasreaper62/Agent-Shield) security SDK for AI agents.

Detect prompt injection, data exfiltration, jailbreaks, and 30+ other AI-specific threats. All detection runs locally. Zero dependencies.

## Install

```bash
pip install agent-shield
```

## Quick Start

```python
from agent_shield import AgentShield

shield = AgentShield(sensitivity="high", block_on_threat=True)

# Scan user input
result = shield.scan_input("ignore all previous instructions")
if result.blocked:
    print("Blocked!", [t.description for t in result.threats])

# Scan agent output
result = shield.scan_output(agent_response)

# Scan tool calls
result = shield.scan_tool_call("bash", {"command": "cat .env"})
```

## PII Redaction

```python
from agent_shield.pii import PIIRedactor

pii = PIIRedactor()
result = pii.redact("Email john@example.com, SSN 123-45-6789")
print(result.redacted)  # "Email [EMAIL_REDACTED], SSN [SSN_REDACTED]"
```

## Testing

```bash
python -m pytest python/tests/
# or
python python/tests/test_detector.py
```

## License

MIT
