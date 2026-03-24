"""Agent Shield — Main Shield Class.

High-level wrapper around the detection engine with stats,
configuration, and framework integration helpers.
"""
from __future__ import annotations

import time
from typing import Any, Callable, Optional

from .detector import scan_text


class AgentShield:
    """AI agent security shield.

    Args:
        config: Optional config dict with block_on_threat, min_severity,
                categories, log_threats, on_threat callback.
    """

    def __init__(self, config: Optional[dict[str, Any]] = None) -> None:
        cfg = config or {}
        self.block_on_threat: bool = cfg.get('block_on_threat', True)
        self.min_severity: str = cfg.get('min_severity', 'low')
        self.categories: Optional[list[str]] = cfg.get('categories')
        self.log_threats: bool = cfg.get('log_threats', True)
        self.on_threat: Optional[Callable] = cfg.get('on_threat')
        self._stats = {
            'total_scans': 0,
            'threats_detected': 0,
            'threats_blocked': 0,
            'history': [],
        }

    def scan(self, text: str) -> dict[str, Any]:
        """Scan text for threats.

        Args:
            text: Text to scan.

        Returns:
            Scan result dict with safe, threats, severity, blocked.
        """
        result = scan_text(text, {
            'min_severity': self.min_severity,
            'categories': self.categories,
        })

        self._stats['total_scans'] += 1

        if not result['safe']:
            self._stats['threats_detected'] += 1
            if self.block_on_threat:
                self._stats['threats_blocked'] += 1
                result['blocked'] = True
            if self.log_threats:
                print(f"[Agent Shield] {len(result['threats'])} threat(s) detected")
            if self.on_threat:
                self.on_threat(result)

        self._stats['history'].append({
            'timestamp': time.time(),
            'safe': result['safe'],
            'threat_count': len(result['threats']),
        })

        return result

    def scan_conversation(self, messages: list[dict[str, str]]) -> dict[str, Any]:
        """Scan a list of conversation messages.

        Args:
            messages: List of dicts with 'role' and 'content' keys.

        Returns:
            Aggregated result with per-message results and overall status.
        """
        results = []
        all_threats = []

        for msg in messages:
            content = msg.get('content', '')
            result = self.scan(content)
            results.append({
                'role': msg.get('role', 'unknown'),
                'result': result,
            })
            all_threats.extend(result.get('threats', []))

        return {
            'safe': len(all_threats) == 0,
            'threats': all_threats,
            'messages': results,
            'message_count': len(messages),
        }

    def wrap_langchain(self, chain: Any) -> Any:
        """Wrap a LangChain chain with input/output scanning.

        Args:
            chain: A LangChain chain or runnable.

        Returns:
            Wrapped chain that scans inputs and outputs.
        """
        shield = self

        class ShieldedChain:
            def __init__(self, inner: Any) -> None:
                self._inner = inner

            def invoke(self, input_data: Any, **kwargs: Any) -> Any:
                text = str(input_data)
                result = shield.scan(text)
                if result.get('blocked'):
                    raise RuntimeError(f"[Agent Shield] Input blocked: {result['severity']}")
                output = self._inner.invoke(input_data, **kwargs)
                out_result = shield.scan(str(output))
                if out_result.get('blocked'):
                    raise RuntimeError(f"[Agent Shield] Output blocked: {out_result['severity']}")
                return output

            def __getattr__(self, name: str) -> Any:
                return getattr(self._inner, name)

        return ShieldedChain(chain)

    def wrap_llamaindex(self, query_engine: Any) -> Any:
        """Wrap a LlamaIndex query engine with scanning.

        Args:
            query_engine: A LlamaIndex query engine.

        Returns:
            Wrapped engine that scans queries and responses.
        """
        shield = self

        class ShieldedEngine:
            def __init__(self, inner: Any) -> None:
                self._inner = inner

            def query(self, query_str: str, **kwargs: Any) -> Any:
                result = shield.scan(query_str)
                if result.get('blocked'):
                    raise RuntimeError(f"[Agent Shield] Query blocked: {result['severity']}")
                response = self._inner.query(query_str, **kwargs)
                out_result = shield.scan(str(response))
                if out_result.get('blocked'):
                    raise RuntimeError(f"[Agent Shield] Response blocked: {out_result['severity']}")
                return response

            def __getattr__(self, name: str) -> Any:
                return getattr(self._inner, name)

        return ShieldedEngine(query_engine)

    @property
    def stats(self) -> dict[str, Any]:
        """Return scan statistics."""
        return self._stats.copy()

    def reset_stats(self) -> None:
        """Reset scan statistics."""
        self._stats = {
            'total_scans': 0,
            'threats_detected': 0,
            'threats_blocked': 0,
            'history': [],
        }
