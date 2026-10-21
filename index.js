#!/usr/bin/env node
/**
 * Panthera x402 v2 Model Context Protocol (MCP) Server (stdio + Remote Gateway proxy)
 * Zero external dependencies — runs on any Node.js >= 18 environment via `npx -y panthera-x402-mcp`
 */

const readline = require('node:readline');

const PANTHERA_MCP_ENDPOINT =
  process.env.PANTHERA_MCP_URL || 'https://rklhfyeyw0.execute-api.ap-south-1.amazonaws.com/mcp';
const DEFAULT_TX_SIG = process.env.PANTHERA_X402_SIGNATURE || '';

const rl = readline.createInterface({
  input: process.stdin,
  terminal: false
});

rl.on('line', async (line) => {
  const trimmed = String(line || '').trim();
  if (!trimmed) return;

  let reqObj;
  try {
    reqObj = JSON.parse(trimmed);
  } catch (e) {
    process.stdout.write(
      JSON.stringify({
        jsonrpc: '2.0',
        id: null,
        error: { code: -32700, message: 'Parse error' }
      }) + '\n'
    );
    return;
  }

  try {
    const headers = {
      'Content-Type': 'application/json',
      Accept: 'application/json'
    };
    if (DEFAULT_TX_SIG) {
      headers['PAYMENT-SIGNATURE'] = DEFAULT_TX_SIG;
    }

    const res = await fetch(PANTHERA_MCP_ENDPOINT, {
      method: 'POST',
      headers,
      body: JSON.stringify(reqObj)
    });

    if (res.status === 202) return;
    const text = await res.text();
    if (text && text.trim()) {
      process.stdout.write(text.trim() + '\n');
    }
  } catch (err) {
    if (reqObj && reqObj.id !== undefined) {
      process.stdout.write(
        JSON.stringify({
          jsonrpc: '2.0',
          id: reqObj.id,
          error: { code: -32603, message: err.message }
        }) + '\n'
      );
    }
  }
});
