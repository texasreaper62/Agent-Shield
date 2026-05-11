/**
 * Agent Shield — Next.js Edge Middleware Example
 *
 * Save as middleware.js (or middleware.ts) at the root of your Next.js app.
 * Scans every request body that hits /api/chat (or whatever routes you choose).
 *
 * Works in:
 *   - Next.js Pages Router (/pages/api/*)
 *   - Next.js App Router (/app/api/*)
 *   - Vercel Edge Runtime
 *
 * Setup:
 *   npm install agentshield-sdk
 */

import { NextResponse } from 'next/server';
import { AgentShield } from 'agentshield-sdk';

const shield = new AgentShield({
  sensitivity: 'high',
  blockOnThreat: true,
  blockThreshold: 'high'
});

export const config = {
  matcher: ['/api/chat/:path*', '/api/agent/:path*']
};

export async function middleware(request) {
  // Read and re-construct the body (middleware can only read once)
  const body = await request.text();
  let parsed;
  try {
    parsed = JSON.parse(body);
  } catch {
    return NextResponse.next();
  }

  // Pull the user message from common shapes
  const userMessage =
    parsed.message ||
    parsed.prompt ||
    parsed.messages?.[parsed.messages.length - 1]?.content ||
    '';

  if (typeof userMessage === 'string' && userMessage.length > 0) {
    const result = shield.scanInput(userMessage);
    if (result.blocked) {
      return NextResponse.json({
        error: 'Request blocked by Agent Shield',
        category: result.threats[0]?.category,
        severity: result.threats[0]?.severity,
        detail: result.threats[0]?.description
      }, { status: 400 });
    }
  }

  // Forward the body to the route handler
  return NextResponse.next({
    request: {
      body
    }
  });
}
