/**
 * Agent Shield — Vercel AI SDK Guardrail Example
 *
 * Wraps a Vercel AI SDK streaming chat endpoint with input + output scanning.
 *
 * Save as: app/api/chat/route.ts (or .js)
 *
 *   npm install agentshield-sdk ai @ai-sdk/anthropic
 */

import { streamText } from 'ai';
import { anthropic } from '@ai-sdk/anthropic';
import { AgentShield } from 'agentshield-sdk';

const shield = new AgentShield({
  sensitivity: 'high',
  blockOnThreat: true,
  blockThreshold: 'high',
  onThreat: (result) => {
    console.log('[Agent Shield] Blocked:', result.threats[0]?.category);
  }
});

export async function POST(req) {
  const { messages } = await req.json();

  // Scan every user message (catches prompt injection in chat history)
  for (const msg of messages) {
    if (msg.role === 'user') {
      const scan = shield.scanInput(typeof msg.content === 'string' ? msg.content : JSON.stringify(msg.content));
      if (scan.blocked) {
        return Response.json({
          error: 'Message blocked by Agent Shield',
          category: scan.threats[0]?.category
        }, { status: 400 });
      }
    }
  }

  const result = streamText({
    model: anthropic('claude-sonnet-4-6'),
    messages
  });

  return result.toDataStreamResponse();
}
