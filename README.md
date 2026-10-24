# Panthera x402 MCP Server (`panthera-x402-mcp`)

[![MCP Server](https://glama.ai/mcp/servers/MrKGaja/panthera-x402-mcp/badges/score.svg)](https://glama.ai/mcp/servers/MrKGaja/panthera-x402-mcp)
[![License: MIT](https://img.shields.io/badge/License-MIT-emerald.svg)](./LICENSE)

An open-source **Model Context Protocol (MCP)** server written in zero-dependency Node.js (`>= 18`) that implements **22 cybersecurity, OSINT, DNS/TLS inspection, and Solana Mainnet JSON-RPC tools** directly in this repository ([`index.js`](./index.js) and [`src/tools.js`](./src/tools.js)).

---

## Repository Architecture & Source Code

Unlike thin proxy wrappers, **this repository contains the complete, self-contained MCP server and tool implementation**:

```text
panthera-x402-mcp/
├── index.js          # MCP JSON-RPC 2.0 server (stdio + optional --http transport)
├── src/
│   └── tools.js      # Full implementation & JSON Schema definitions for all 22 tools
├── Dockerfile        # Self-contained container build (node:20-alpine)
├── package.json      # Zero external runtime dependencies (uses Node.js built-ins)
├── glama.json        # Glama MCP directory metadata
├── smithery.yaml     # Smithery container & stdio runtime specification
└── LICENSE           # MIT License
```

### How It Works Internally
- **MCP Protocol Handler ([`index.js`](./index.js))**: Implements JSON-RPC 2.0 `initialize`, `ping`, `tools/list`, `tools/call`, `resources/list`, and `prompts/list` over standard `stdio` (default) or local HTTP (`node index.js --http`).
- **Tool Execution Engine ([`src/tools.js`](./src/tools.js))**: Uses Node.js built-in modules (`node:dns/promises`, `node:tls`, `node:crypto`, and native `fetch`) to execute DNS MX/SPF/DMARC resolution, X.509 TLS certificate chain grading, Certificate Transparency (`crt.sh`) subdomain enumeration, Solana Mainnet JSON-RPC calls (`getBalance`, `getAccountInfo`, `simulateTransaction`, `getRecentPrioritizationFees`, `getTokenLargestAccounts`), URL-to-Markdown conversion, IDN punycode phishing analysis, and multi-platform OSINT checks directly on your machine.

---

## Installation & Running Locally from Source

### 1. Clone and Run Directly with Node.js (`>= 18`)
```bash
git clone https://github.com/MrKGaja/panthera-x402-mcp.git
cd panthera-x402-mcp
node index.js
```

### 2. Verify with a Local MCP `tools/list` Handshake
```bash
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | node index.js
```

### 3. Build and Run with Docker
```bash
docker build -t panthera-x402-mcp .
docker run -i --rm panthera-x402-mcp
```

---

## Configuration for Claude Desktop, Cursor, Windsurf & Cline

### Local `npx` / GitHub Source Setup
```json
{
  "mcpServers": {
    "panthera-x402": {
      "command": "npx",
      "args": ["-y", "github:MrKGaja/panthera-x402-mcp"],
      "env": {
        "SOLANA_RPC_URL": "https://api.mainnet-beta.solana.com"
      }
    }
  }
}
```

### Local Clone Setup
```json
{
  "mcpServers": {
    "panthera-x402": {
      "command": "node",
      "args": ["/absolute/path/to/panthera-x402-mcp/index.js"]
    }
  }
}
```

---

## Environment Variables (Optional)

| Variable | Default | Description |
| :--- | :--- | :--- |
| `SOLANA_RPC_URL` | `https://api.mainnet-beta.solana.com` | Solana Mainnet RPC endpoint used by Solana tools in `src/tools.js`. |
| `MCP_TRANSPORT` | `stdio` | Set to `http` (or pass `--http`) to expose a local HTTP server on `PORT` (default `3333`). |
| `PORT` | `3333` | Port used when running in `--http` mode. |

---

## All 22 Open-Source Tools Implemented in `src/tools.js`

| # | Tool Name | Implementation in `src/tools.js` |
| :- | :--- | :--- |
| 1 | `panthera_solana_rpc` | Executes arbitrary Solana Mainnet JSON-RPC 2.0 methods (`getSlot`, `getBalance`, `getLatestBlockhash`, `getAccountInfo`, etc.). |
| 2 | `panthera_solana_priority_fee` | Queries `getRecentPrioritizationFees` & `getRecentPerformanceSamples` to compute p25/p50/p75/p90 micro-lamport fee percentiles and live TPS. |
| 3 | `panthera_simulate_solana_tx` | Runs `simulateTransaction` on serialized transactions and scans execution logs for wallet-drainer instructions (`SetAuthority`, `Approve`, `CloseAccount`). |
| 4 | `panthera_solana_wallet_profile` | Queries `getBalance`, USDC `getTokenAccountsByOwner`, and `getSignaturesForAddress` for any Solana wallet. |
| 5 | `panthera_solana_token_audit` | Audits SPL token mints via `getAccountInfo` (`jsonParsed`) and `getTokenLargestAccounts` for active Mint/Freeze authorities and top-10 whale concentration. |
| 6 | `panthera_verify_email` | Performs live DNS `resolveMx` and `resolveTxt` (`v=spf1`, `_dmarc`) checks via `node:dns` and flags disposable email providers. |
| 7 | `panthera_domain_recon` | Resolves `A`, `AAAA`, `MX`, `NS`, `TXT`, and `_dmarc` records and queries `crt.sh` Certificate Transparency logs for subdomains. |
| 8 | `panthera_ssl_tls_grade` | Opens a TLS handshake via `node:tls` (`getPeerCertificate`, `getProtocol`, `getCipher`) and inspects HSTS/CSP/XFO security headers to grade hosts `A+` to `F`. |
| 9 | `panthera_phishing_url_check` | Detects IDN punycode (`xn--`) homographs, brand typosquatting, raw IP literals, and high-risk TLDs. |
| 10 | `panthera_scrape_markdown` | Fetches web pages and strips scripts/styles to return clean Markdown text and page titles. |
| 11 | `panthera_live_search` | Queries HackerNews Algolia search API for technical & security intelligence results. |
| 12 | `panthera_username_osint` | Checks username existence across GitHub, GitLab, HackerNews, and npm registries in parallel. |
| 13 | `panthera_check_ip_threat` | Performs reverse DNS (`dns.reverse`), ASN/ISP lookup, and datacenter/proxy classification for an IP address. |
| 14 | `panthera_ip_fraud_score` | Calculates a composite fraud & bot score (`0-100`) from ASN, ISP, and reverse DNS telemetry. |
| 15 | `panthera_bulk_check_ips` | Batch-audits up to 100 IPv4/IPv6 addresses concurrently. |
| 16 | `panthera_email_breach_check` | Computes Gravatar MD5 identity hashes and audits the email domain's MX/SPF/DMARC security posture. |
| 17 | `panthera_darkweb_search` | Generates Tor `.onion` hidden-service search descriptors via the Ahmia index. |
| 18 | `panthera_reverse_image_osint` | Inspects image HTTP headers (`content-type`, `content-length`) and builds Google Lens, Yandex, and TinEye OSINT pivot URLs. |
| 19 | `panthera_webhook_inbox` | Creates and polls ephemeral 24-hour webhook inboxes (`create`, `push`, `poll`) for NAT/sandboxed agents. |
| 20 | `panthera_threat_intel_feed` | Retrieves active honeypot scanner signatures and x402 security manifest metadata. |
| 21 | `panthera_chat_completions` | Security-focused assistant completion handler with tool recommendations. |
| 22 | `panthera_unban_ip` | Prepares and submits an IP quarantine clearance request with optional Solana x402 transaction signature. |

---

## License

MIT © [Panthera Security Operations](./LICENSE)
