# Panthera x402 v2 MCP Server (`panthera-x402-mcp`)

22 pay-per-call **x402 v2** tools on **Solana Mainnet USDC** (`EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v`) for Claude Desktop, Cursor, Windsurf, Cline, OpenClaw, and autonomous AI agents.

- **Remote Streamable HTTP MCP Endpoint**: `https://rklhfyeyw0.execute-api.ap-south-1.amazonaws.com/mcp`
- **x402scan Server Page**: https://www.x402scan.com/server/293f0905-4549-4bf0-95b3-db8c4df1dbee
- **OpenAPI 3.1.0 Spec**: `https://rklhfyeyw0.execute-api.ap-south-1.amazonaws.com/openapi.json`
- **Agent SKILL.md**: `https://rklhfyeyw0.execute-api.ap-south-1.amazonaws.com/SKILL.md`

## 1-Line Setup (Claude Desktop / Cursor / Windsurf)

### Option A: Direct Streamable HTTP (Zero Install)
```json
{
  "mcpServers": {
    "panthera-x402": {
      "url": "https://rklhfyeyw0.execute-api.ap-south-1.amazonaws.com/mcp"
    }
  }
}
```

### Option B: Local `npx` stdio Wrapper
```json
{
  "mcpServers": {
    "panthera-x402": {
      "command": "npx",
      "args": ["-y", "panthera-x402-mcp"]
    }
  }
}
```

## Included 22 x402 Tools
1. `panthera_chat_completions` (`$0.001 USDC`) — Drop-in OpenAI `/v1/chat/completions` LLM inference enriched with live Panthera Honeypot Threat-Intel.
2. `panthera_live_search` (`$0.002 USDC`) — Live Web, HackerNews & Threat-Intel Search API.
3. `panthera_solana_rpc` (`$0.001 USDC`) — Solana Mainnet JSON-RPC 2.0 passthrough (`getSlot`, `getBalance`, `getLatestBlockhash`, `getAccountInfo`, etc.).
4. `panthera_scrape_markdown` (`$0.01 USDC`) — Clean URL-to-Markdown, OpenGraph & JSON-LD extractor.
5. `panthera_simulate_solana_tx` (`$0.01 USDC`) — Solana transaction pre-flight simulator & wallet-drainer guard.
6. `panthera_webhook_inbox` (`$0.02 USDC`) — 24h public HTTPS webhook drop URL & polling inbox for NAT/sandboxed agents.
7. `panthera_solana_priority_fee` (`$0.005 USDC`) — Live Solana priority-fee percentiles (p25/p50/p75/p90) & TPS oracle.
8. `panthera_verify_email` (`$0.005 USDC`) — Live DNS MX, SPF/DMARC & 500+ disposable/burner email gatekeeper.
9. `panthera_check_ip_threat` (`$0.01 USDC`) — Single-IP Honeypot reputation & attack telemetry.
10. `panthera_threat_intel_feed` (`$0.05 USDC`) — Live feed of up to 500 verified malicious scanner IPs.
11. `panthera_bulk_check_ips` (`$0.10 USDC`) — Batch-audit up to 100 IPs in a single call.
12. `panthera_ip_fraud_score` (`$0.01 USDC`) — Composite IP fraud score (AbuseIPDB + IPQualityScore + Honeypot).
13. `panthera_domain_recon` (`$0.02 USDC`) — Live Domain DNS, SPF/DMARC, RDAP WHOIS & crt.sh SSL subdomains.
14. `panthera_username_osint` (`$0.02 USDC`) — Cross-platform developer & social username OSINT.
15. `panthera_email_breach_check` (`$0.02 USDC`) — Email credential breach history & Dark Web infostealer check.
16. `panthera_darkweb_search` (`$0.03 USDC`) — Tor `.onion` Dark Web hidden service mentions search.
17. `panthera_solana_wallet_profile` (`$0.01 USDC`) — Solana Mainnet wallet SOL/USDC balances & USD valuation.
18. `panthera_solana_token_audit` (`$0.02 USDC`) — Solana SPL token rug-pull, Mint/Freeze authority & whale audit.
19. `panthera_phishing_url_check` (`$0.01 USDC`) — Real-time phishing URL, IDN homograph (`xn--`) & brand spoofing detector.
20. `panthera_ssl_tls_grade` (`$0.02 USDC`) — Automated SSL/TLS certificate & HTTP security header grader (`A+` to `F`).
21. `panthera_reverse_image_osint` (`$0.05 USDC`) — Reverse image & avatar visual OSINT correlation.
22. `panthera_unban_ip` (`$25.00 USDC`) — Automated self-unban security clearance bond.
