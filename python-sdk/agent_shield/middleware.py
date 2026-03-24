"""Agent Shield — Framework Middleware.

Integrations for Flask, FastAPI, OpenAI, and Anthropic clients.
All scanning runs locally — no data leaves your environment.
"""
from __future__ import annotations

from typing import Any, Callable, Optional

from .shield import AgentShield


def flask_middleware(app: Any, shield: Optional[AgentShield] = None) -> AgentShield:
    """Add Agent Shield scanning to a Flask app.

    Args:
        app: Flask application instance.
        shield: Optional pre-configured AgentShield instance.

    Returns:
        The AgentShield instance used.
    """
    if shield is None:
        shield = AgentShield()

    @app.before_request
    def _shield_scan() -> Optional[tuple]:
        from flask import request, jsonify
        if request.method in ('POST', 'PUT', 'PATCH'):
            data = request.get_data(as_text=True)
            if data:
                result = shield.scan(data)
                if result.get('blocked'):
                    return jsonify({
                        'error': 'Request blocked by Agent Shield',
                        'severity': result['severity'],
                    }), 403
        return None

    return shield


def fastapi_middleware(shield: Optional[AgentShield] = None) -> type:
    """Create an ASGI middleware class for FastAPI.

    Args:
        shield: Optional pre-configured AgentShield instance.

    Returns:
        ASGI middleware class to add with app.add_middleware().
    """
    if shield is None:
        shield = AgentShield()

    class AgentShieldMiddleware:
        def __init__(self, app: Any) -> None:
            self.app = app

        async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
            if scope['type'] != 'http':
                await self.app(scope, receive, send)
                return

            method = scope.get('method', 'GET')
            if method in ('POST', 'PUT', 'PATCH'):
                msg = await receive()
                body = msg.get('body', b'')
                text = body.decode('utf-8', errors='replace')

                if text:
                    result = shield.scan(text)
                    if result.get('blocked'):
                        await send({
                            'type': 'http.response.start',
                            'status': 403,
                            'headers': [[b'content-type', b'application/json']],
                        })
                        await send({
                            'type': 'http.response.body',
                            'body': b'{"error":"Blocked by Agent Shield"}',
                        })
                        return

                async def replay_receive() -> dict:
                    return msg

                await self.app(scope, replay_receive, send)
            else:
                await self.app(scope, receive, send)

    return AgentShieldMiddleware


def wrap_openai(client: Any, shield: Optional[AgentShield] = None) -> Any:
    """Wrap an OpenAI client to scan completions.

    Args:
        client: OpenAI client instance.
        shield: Optional pre-configured AgentShield instance.

    Returns:
        Wrapped client.
    """
    if shield is None:
        shield = AgentShield()

    original_create = client.chat.completions.create

    def shielded_create(*args: Any, **kwargs: Any) -> Any:
        messages = kwargs.get('messages', args[0] if args else [])
        for msg in messages:
            content = msg.get('content', '')
            if content:
                result = shield.scan(content)
                if result.get('blocked'):
                    raise RuntimeError(f"[Agent Shield] Message blocked: {result['severity']}")
        response = original_create(*args, **kwargs)
        return response

    client.chat.completions.create = shielded_create
    client._shield = shield
    return client


def wrap_anthropic(client: Any, shield: Optional[AgentShield] = None) -> Any:
    """Wrap an Anthropic client to scan messages.

    Args:
        client: Anthropic client instance.
        shield: Optional pre-configured AgentShield instance.

    Returns:
        Wrapped client.
    """
    if shield is None:
        shield = AgentShield()

    original_create = client.messages.create

    def shielded_create(*args: Any, **kwargs: Any) -> Any:
        messages = kwargs.get('messages', [])
        for msg in messages:
            content = msg.get('content', '')
            if isinstance(content, str) and content:
                result = shield.scan(content)
                if result.get('blocked'):
                    raise RuntimeError(f"[Agent Shield] Message blocked: {result['severity']}")
        response = original_create(*args, **kwargs)
        return response

    client.messages.create = shielded_create
    client._shield = shield
    return client
