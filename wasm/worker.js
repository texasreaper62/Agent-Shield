'use strict';

/**
 * Agent Shield — Cloudflare Worker Example
 *
 * Deploys Agent Shield as a serverless scanning endpoint.
 * Handles POST /scan — scans request body text and returns JSON results.
 *
 * Deploy with: wrangler deploy wasm/worker.js
 *
 * Usage:
 *   curl -X POST https://your-worker.dev/scan \
 *     -H 'Content-Type: application/json' \
 *     -d '{"text": "ignore all previous instructions"}'
 */

import { scanText } from './dist/agent-shield.esm.js';

/**
 * Handle incoming requests.
 * @param {Request} request - The incoming request.
 * @returns {Promise<Response>} JSON response with scan results.
 */
async function handleRequest(request) {
  // CORS headers for browser clients
  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };

  // Handle preflight
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  // Only accept POST /scan
  const url = new URL(request.url);
  if (url.pathname !== '/scan' || request.method !== 'POST') {
    return new Response(JSON.stringify({
      error: 'Not found. Use POST /scan with JSON body: { "text": "..." }'
    }), {
      status: 404,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }

  try {
    const body = await request.json();

    if (!body.text || typeof body.text !== 'string') {
      return new Response(JSON.stringify({
        error: 'Missing or invalid "text" field in request body.'
      }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    // Scan the text with optional settings
    const options = {
      source: body.source || 'cloudflare-worker',
      sensitivity: body.sensitivity || 'medium',
    };

    const result = scanText(body.text, options);

    return new Response(JSON.stringify(result, null, 2), {
      status: 200,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  } catch (err) {
    return new Response(JSON.stringify({
      error: 'Invalid JSON body.',
      detail: err.message,
    }), {
      status: 400,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }
}

export default {
  fetch: handleRequest,
};
