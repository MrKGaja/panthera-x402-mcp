#!/usr/bin/env node
/**
 * Panthera x402 v2 Open-Source Model Context Protocol (MCP) Server
 * Implements the full MCP JSON-RPC 2.0 specification (stdio + optional HTTP server)
 * and executes all 22 OSINT, cybersecurity, and Solana Mainnet tools locally from ./src/tools.js.
 */

const readline = require('node:readline');
const http = require('node:http');
const { MCP_TOOLS, executeTool } = require('./src/tools');

const SERVER_INFO = {
  name: 'panthera-x402-mcp',
  version: '2.5.0'
};

/**
 * Process a single MCP JSON-RPC 2.0 request object
 */
async function handleJsonRpcMessage(reqObj) {
  if (!reqObj || typeof reqObj !== 'object') {
    return {
      jsonrpc: '2.0',
      id: null,
      error: { code: -32600, message: 'Invalid Request' }
    };
  }

  const { id, method, params } = reqObj;

  // Notifications (no id) do not return a response frame
  if (id === undefined || id === null) {
    return null;
  }

  try {
    switch (method) {
      case 'initialize':
        return {
          jsonrpc: '2.0',
          id,
          result: {
            protocolVersion: (params && params.protocolVersion) || '2024-11-05',
            capabilities: {
              tools: { listChanged: false },
              resources: {},
              prompts: {}
            },
            serverInfo: SERVER_INFO
          }
        };

      case 'ping':
        return {
          jsonrpc: '2.0',
          id,
          result: {}
        };

      case 'tools/list':
        return {
          jsonrpc: '2.0',
          id,
          result: {
            tools: MCP_TOOLS
          }
        };

      case 'resources/list':
        return {
          jsonrpc: '2.0',
          id,
          result: {
            resources: []
          }
        };

      case 'prompts/list':
        return {
          jsonrpc: '2.0',
          id,
          result: {
            prompts: []
          }
        };

      case 'tools/call': {
        const toolName = params && params.name;
        const toolArgs = (params && params.arguments) || {};
        if (!toolName) {
          return {
            jsonrpc: '2.0',
            id,
            error: { code: -32602, message: 'Missing tool name in tools/call' }
          };
        }

        const output = await executeTool(toolName, toolArgs);
        return {
          jsonrpc: '2.0',
          id,
          result: {
            content: [
              {
                type: 'text',
                text: JSON.stringify(output, null, 2)
              }
            ],
            isError: false
          }
        };
      }

      default:
        return {
          jsonrpc: '2.0',
          id,
          error: {
            code: -32601,
            message: `Method not found: ${method}`
          }
        };
    }
  } catch (err) {
    return {
      jsonrpc: '2.0',
      id,
      result: {
        content: [
          {
            type: 'text',
            text: JSON.stringify({ error: err.message }, null, 2)
          }
        ],
        isError: true
      }
    };
  }
}

// Optional local Streamable HTTP transport when started with `--http` or `MCP_TRANSPORT=http`
if (process.argv.includes('--http') || process.env.MCP_TRANSPORT === 'http') {
  const port = Number(process.env.PORT || 3333);
  const server = http.createServer((req, res) => {
    if (req.method === 'GET' && req.url === '/health') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, server: SERVER_INFO, tools: MCP_TOOLS.length }));
      return;
    }
    if (req.method !== 'POST') {
      res.writeHead(405, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Use POST with MCP JSON-RPC 2.0 payload' }));
      return;
    }
    let body = '';
    req.on('data', (chunk) => {
      body += chunk;
    });
    req.on('end', async () => {
      try {
        const parsed = JSON.parse(body);
        const reply = await handleJsonRpcMessage(parsed);
        if (!reply) {
          res.writeHead(202);
          res.end();
          return;
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(reply));
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            jsonrpc: '2.0',
            id: null,
            error: { code: -32700, message: 'Parse error' }
          })
        );
      }
    });
  });
  server.listen(port, () => {
    process.stderr.write(`Panthera MCP Server listening on http://localhost:${port}\n`);
  });
} else {
  // Default MCP stdio transport
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

    const response = await handleJsonRpcMessage(reqObj);
    if (response) {
      process.stdout.write(JSON.stringify(response) + '\n');
    }
  });
}
