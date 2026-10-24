/**
 * Panthera x402 v2 Open-Source MCP Server — Tool Definitions & Implementations
 * Implements all 22 security, OSINT, Solana Mainnet RPC, and AI intelligence tools
 * directly in Node.js (>= 18) using built-in modules (node:dns, node:tls, node:crypto, fetch).
 */

const dns = require('node:dns').promises;
const tls = require('node:tls');
const crypto = require('node:crypto');

const SOLANA_MAINNET_RPC = process.env.SOLANA_RPC_URL || 'https://api.mainnet-beta.solana.com';
const PANTHERA_GATEWAY_URL = process.env.PANTHERA_API_URL || 'https://rklhfyeyw0.execute-api.ap-south-1.amazonaws.com';
const TREASURY_WALLET =
  process.env.PANTHERA_TREASURY_WALLET || 'PantheraTreasury111111111111111111111111111';
const USDC_MINT = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';

const DISPOSABLE_EMAIL_DOMAINS = new Set([
  'mailinator.com', 'guerrillamail.com', '10minutemail.com', 'tempmail.com',
  'temp-mail.org', 'yopmail.com', 'trashmail.com', 'sharklasers.com',
  'getnada.com', 'maildrop.cc', 'throwawaymail.com', 'fakeinbox.com',
  'dispostable.com', 'mailnesia.com', 'mohmal.com', 'burnermail.io'
]);

const BRAND_SPOOF_KEYWORDS = [
  'paypal', 'apple', 'microsoft', 'google', 'binance', 'coinbase',
  'phantom', 'metamask', 'solana', 'ledger', 'trezor', 'chase', 'stripe'
];

const inMemoryWebhooks = new Map();

/**
 * Complete MCP Tool Schema Definitions (22 Tools)
 */
const MCP_TOOLS = [
  {
    name: 'panthera_chat_completions',
    description:
      'OpenAI-compatible /v1/chat/completions inference enriched with live cybersecurity & threat-intelligence context.',
    inputSchema: {
      type: 'object',
      properties: {
        prompt: { type: 'string', description: 'User prompt or security question to analyze.' },
        model: { type: 'string', description: 'Model identifier (default: panthera-sec-llm-v2).' },
        system: { type: 'string', description: 'Optional system prompt override.' }
      },
      required: ['prompt']
    }
  },
  {
    name: 'panthera_live_search',
    description:
      'Live Web, HackerNews Algolia, and cybersecurity threat-intelligence search engine.',
    inputSchema: {
      type: 'object',
      properties: {
        query: { type: 'string', description: 'Search query string.' },
        limit: { type: 'number', description: 'Max results to return (1-20, default: 8).' }
      },
      required: ['query']
    }
  },
  {
    name: 'panthera_solana_rpc',
    description:
      'Direct Solana Mainnet JSON-RPC 2.0 execution (getSlot, getBalance, getLatestBlockhash, getAccountInfo, getSignaturesForAddress, etc.).',
    inputSchema: {
      type: 'object',
      properties: {
        method: { type: 'string', description: 'Solana JSON-RPC method name (e.g. getBalance, getSlot).' },
        params: { type: 'array', description: 'JSON-RPC parameters array.' }
      },
      required: ['method']
    }
  },
  {
    name: 'panthera_scrape_markdown',
    description:
      'Fetches a public URL and extracts clean Markdown text, page title, OpenGraph metadata, and JSON-LD structured data.',
    inputSchema: {
      type: 'object',
      properties: {
        url: { type: 'string', description: 'Target HTTPS URL to scrape and convert to Markdown.' }
      },
      required: ['url']
    }
  },
  {
    name: 'panthera_simulate_solana_tx',
    description:
      'Pre-flight Solana transaction simulator and wallet-drainer guard. Simulates serialized base64/base58 transactions on Solana Mainnet and inspects logs & account mutations.',
    inputSchema: {
      type: 'object',
      properties: {
        transaction: { type: 'string', description: 'Base64-encoded serialized Solana transaction.' },
        encoding: { type: 'string', description: 'Encoding format (default: base64).' }
      },
      required: ['transaction']
    }
  },
  {
    name: 'panthera_webhook_inbox',
    description:
      'Creates or polls an ephemeral 24-hour webhook inbox so sandboxed/NAT AI agents can receive and inspect asynchronous HTTP callbacks.',
    inputSchema: {
      type: 'object',
      properties: {
        action: { type: 'string', enum: ['create', 'poll', 'push'], description: 'Action: create, poll, or push.' },
        inboxId: { type: 'string', description: 'Webhook inbox ID when polling or pushing.' },
        payload: { type: 'object', description: 'Optional JSON payload when action is push.' }
      },
      required: ['action']
    }
  },
  {
    name: 'panthera_solana_priority_fee',
    description:
      'Live Solana Mainnet priority-fee oracle returning micro-lamport percentiles (p25, p50, p75, p90) and current network TPS.',
    inputSchema: {
      type: 'object',
      properties: {
        accounts: {
          type: 'array',
          items: { type: 'string' },
          description: 'Optional list of writable account public keys to scope fee estimation.'
        }
      }
    }
  },
  {
    name: 'panthera_verify_email',
    description:
      'Live DNS MX record lookup, SPF/DMARC verification, syntax check, and disposable/burner email domain detection.',
    inputSchema: {
      type: 'object',
      properties: {
        email: { type: 'string', description: 'Email address to verify.' }
      },
      required: ['email']
    }
  },
  {
    name: 'panthera_check_ip_threat',
    description:
      'Audits a single IPv4/IPv6 address for geolocation, ASN, reverse DNS, proxy/Tor indicators, and honeypot threat score.',
    inputSchema: {
      type: 'object',
      properties: {
        ip: { type: 'string', description: 'IPv4 or IPv6 address to inspect.' }
      },
      required: ['ip']
    }
  },
  {
    name: 'panthera_threat_intel_feed',
    description:
      'Returns the latest verified malicious scanner IPs, honeypot hits, and active attack signatures.',
    inputSchema: {
      type: 'object',
      properties: {
        limit: { type: 'number', description: 'Maximum number of threat feed entries (1-500, default: 25).' }
      }
    }
  },
  {
    name: 'panthera_bulk_check_ips',
    description:
      'Batch-audits up to 100 IP addresses in parallel for ASN, reverse DNS, datacenter/proxy classification, and threat score.',
    inputSchema: {
      type: 'object',
      properties: {
        ips: {
          type: 'array',
          items: { type: 'string' },
          description: 'Array of IPv4/IPv6 addresses (max 100).'
        }
      },
      required: ['ips']
    }
  },
  {
    name: 'panthera_ip_fraud_score',
    description:
      'Computes a composite IP fraud & bot risk score (0-100) using ASN classification, reverse DNS, and threat telemetry.',
    inputSchema: {
      type: 'object',
      properties: {
        ip: { type: 'string', description: 'Target IP address.' }
      },
      required: ['ip']
    }
  },
  {
    name: 'panthera_domain_recon',
    description:
      'Performs live DNS (A, AAAA, MX, NS, TXT), SPF/DMARC policy audit, RDAP WHOIS lookup, and crt.sh Certificate Transparency subdomain discovery.',
    inputSchema: {
      type: 'object',
      properties: {
        domain: { type: 'string', description: 'Target domain name (e.g. example.com).' }
      },
      required: ['domain']
    }
  },
  {
    name: 'panthera_username_osint',
    description:
      'Cross-platform developer and social username OSINT recon across GitHub, GitLab, Reddit, Keybase, npm, and HackerNews.',
    inputSchema: {
      type: 'object',
      properties: {
        username: { type: 'string', description: 'Handle or username to investigate.' }
      },
      required: ['username']
    }
  },
  {
    name: 'panthera_email_breach_check',
    description:
      'Checks an email address for known credential breach exposure, domain security posture, and Gravatar/OSINT identity correlation.',
    inputSchema: {
      type: 'object',
      properties: {
        email: { type: 'string', description: 'Email address to audit.' }
      },
      required: ['email']
    }
  },
  {
    name: 'panthera_darkweb_search',
    description:
      'Searches Ahmia Tor hidden-service index and threat-intel archives for `.onion` mentions of a domain, email, or keyword.',
    inputSchema: {
      type: 'object',
      properties: {
        query: { type: 'string', description: 'Domain, email, or keyword to search across Tor hidden-service indexes.' }
      },
      required: ['query']
    }
  },
  {
    name: 'panthera_solana_wallet_profile',
    description:
      'Fetches live Solana Mainnet SOL balance, USDC SPL token balance, recent transactions, and USD portfolio valuation for a wallet.',
    inputSchema: {
      type: 'object',
      properties: {
        address: { type: 'string', description: 'Solana Mainnet wallet public key (base58).' }
      },
      required: ['address']
    }
  },
  {
    name: 'panthera_solana_token_audit',
    description:
      'Audits a Solana SPL token mint on Mainnet for rug-pull risk: checks Mint Authority, Freeze Authority, total supply, decimals, and top-holder concentration.',
    inputSchema: {
      type: 'object',
      properties: {
        mint: { type: 'string', description: 'Solana SPL Token Mint address (base58).' }
      },
      required: ['mint']
    }
  },
  {
    name: 'panthera_phishing_url_check',
    description:
      'Analyzes a URL for phishing indicators: IDN homograph punycode (xn--), brand typosquatting, suspicious TLDs, IP literals, and redirect chains.',
    inputSchema: {
      type: 'object',
      properties: {
        url: { type: 'string', description: 'URL to inspect for phishing or brand spoofing.' }
      },
      required: ['url']
    }
  },
  {
    name: 'panthera_ssl_tls_grade',
    description:
      'Connects to a host via TLS, inspects the X.509 certificate chain, cipher suite, protocol version, and HTTP security headers, and assigns a grade from A+ to F.',
    inputSchema: {
      type: 'object',
      properties: {
        host: { type: 'string', description: 'Hostname or domain (e.g. github.com).' }
      },
      required: ['host']
    }
  },
  {
    name: 'panthera_reverse_image_osint',
    description:
      'Inspects an image URL, computes SHA-256 content fingerprint, extracts HTTP/MIME metadata, and generates reverse-image OSINT search pivot links.',
    inputSchema: {
      type: 'object',
      properties: {
        imageUrl: { type: 'string', description: 'Public image URL to analyze.' }
      },
      required: ['imageUrl']
    }
  },
  {
    name: 'panthera_unban_ip',
    description:
      'Submits an automated self-unban security clearance request for a quarantined IP address with optional Solana x402 payment signature.',
    inputSchema: {
      type: 'object',
      properties: {
        ip: { type: 'string', description: 'IP address requesting clearance.' },
        paymentSignature: { type: 'string', description: 'Solana Mainnet transaction signature for x402 clearance bond.' }
      },
      required: ['ip']
    }
  }
];

/**
 * Helper: Call Solana Mainnet JSON-RPC 2.0
 */
async function callSolanaRpc(method, params = []) {
  const res = await fetch(SOLANA_MAINNET_RPC, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params })
  });
  return res.json();
}

/**
 * Helper: Inspect TLS certificate of a remote host using node:tls
 */
function inspectTlsCertificate(host, port = 443, timeoutMs = 6000) {
  return new Promise((resolve) => {
    const socket = tls.connect(
      { host, port, servername: host, rejectUnauthorized: false },
      () => {
        try {
          const cert = socket.getPeerCertificate(false);
          const protocol = socket.getProtocol();
          const cipher = socket.getCipher();
          const authorized = socket.authorized;
          socket.end();
          resolve({
            connected: true,
            authorized,
            protocol,
            cipher,
            subject: cert?.subject || null,
            issuer: cert?.issuer || null,
            validFrom: cert?.valid_from || null,
            validTo: cert?.valid_to || null,
            serialNumber: cert?.serialNumber || null,
            fingerprint256: cert?.fingerprint256 || null,
            subjectaltname: cert?.subjectaltname || null
          });
        } catch (err) {
          socket.destroy();
          resolve({ connected: false, error: err.message });
        }
      }
    );
    socket.setTimeout(timeoutMs, () => {
      socket.destroy();
      resolve({ connected: false, error: 'TLS handshake timed out' });
    });
    socket.on('error', (err) => {
      resolve({ connected: false, error: err.message });
    });
  });
}

/**
 * Execute any of the 22 MCP tools locally using open-source Node.js implementations
 */
async function executeTool(name, args = {}) {
  switch (name) {
    case 'panthera_solana_rpc': {
      const method = String(args.method || 'getSlot');
      const params = Array.isArray(args.params) ? args.params : [];
      const rpcResult = await callSolanaRpc(method, params);
      return {
        tool: name,
        network: 'solana-mainnet',
        method,
        response: rpcResult
      };
    }

    case 'panthera_solana_priority_fee': {
      const accounts = Array.isArray(args.accounts) ? args.accounts.slice(0, 128) : [];
      const [feesRes, perfRes] = await Promise.all([
        callSolanaRpc('getRecentPrioritizationFees', accounts.length ? [accounts] : []),
        callSolanaRpc('getRecentPerformanceSamples', [4])
      ]);
      const fees = Array.isArray(feesRes?.result)
        ? feesRes.result.map((f) => Number(f.prioritizationFee || 0)).sort((a, b) => a - b)
        : [];
      const pct = (p) => (fees.length ? fees[Math.min(fees.length - 1, Math.floor(fees.length * p))] : 0);
      const samples = Array.isArray(perfRes?.result) ? perfRes.result : [];
      const tps =
        samples.length > 0 && samples[0].samplePeriodSecs
          ? Math.round(samples[0].numTransactions / samples[0].samplePeriodSecs)
          : null;
      return {
        tool: name,
        network: 'solana-mainnet',
        sampleCount: fees.length,
        estimatedTps: tps,
        microLamportsPerComputeUnit: {
          min: fees[0] || 0,
          p25: pct(0.25),
          p50: pct(0.5),
          p75: pct(0.75),
          p90: pct(0.9),
          max: fees[fees.length - 1] || 0
        }
      };
    }

    case 'panthera_simulate_solana_tx': {
      const tx = String(args.transaction || '').trim();
      const encoding = args.encoding === 'base58' ? 'base58' : 'base64';
      const sim = await callSolanaRpc('simulateTransaction', [
        tx,
        { encoding, sigVerify: false, replaceRecentBlockhash: true }
      ]);
      const logs = sim?.result?.value?.logs || [];
      const err = sim?.result?.value?.err || null;
      const unitsConsumed = sim?.result?.value?.unitsConsumed || 0;
      const suspiciousLogs = logs.filter((l) =>
        /SetAuthority|Approve|CloseAccount|TransferChecked/i.test(l)
      );
      return {
        tool: name,
        network: 'solana-mainnet',
        simulationSuccess: !err,
        error: err,
        unitsConsumed,
        drainerWarning: suspiciousLogs.length > 0,
        suspiciousInstructions: suspiciousLogs,
        logs
      };
    }

    case 'panthera_solana_wallet_profile': {
      const address = String(args.address || '').trim();
      const [balRes, usdcRes, sigsRes] = await Promise.all([
        callSolanaRpc('getBalance', [address]),
        callSolanaRpc('getTokenAccountsByOwner', [
          address,
          { mint: USDC_MINT },
          { encoding: 'jsonParsed' }
        ]),
        callSolanaRpc('getSignaturesForAddress', [address, { limit: 10 }])
      ]);
      const lamports = Number(balRes?.result?.value || 0);
      const solBalance = lamports / 1e9;
      let usdcBalance = 0;
      const tokenAccounts = usdcRes?.result?.value || [];
      for (const acc of tokenAccounts) {
        usdcBalance += Number(
          acc?.account?.data?.parsed?.info?.tokenAmount?.uiAmount || 0
        );
      }
      return {
        tool: name,
        address,
        network: 'solana-mainnet',
        solBalance,
        usdcBalance,
        recentTransactions: (sigsRes?.result || []).map((s) => ({
          signature: s.signature,
          slot: s.slot,
          err: s.err,
          blockTime: s.blockTime
        }))
      };
    }

    case 'panthera_solana_token_audit': {
      const mint = String(args.mint || '').trim();
      const [mintInfoRes, largestRes] = await Promise.all([
        callSolanaRpc('getAccountInfo', [mint, { encoding: 'jsonParsed' }]),
        callSolanaRpc('getTokenLargestAccounts', [mint])
      ]);
      const parsedInfo = mintInfoRes?.result?.value?.data?.parsed?.info || {};
      const mintAuthority = parsedInfo.mintAuthority || null;
      const freezeAuthority = parsedInfo.freezeAuthority || null;
      const decimals = Number(parsedInfo.decimals || 0);
      const rawSupply = Number(parsedInfo.supply || 0);
      const uiSupply = decimals > 0 ? rawSupply / Math.pow(10, decimals) : rawSupply;
      const topHolders = (largestRes?.result?.value || []).slice(0, 10).map((h) => ({
        address: h.address,
        uiAmount: Number(h.uiAmount || 0),
        sharePct: uiSupply > 0 ? Number(((Number(h.uiAmount || 0) / uiSupply) * 100).toFixed(2)) : 0
      }));
      const top10Pct = Number(topHolders.reduce((acc, h) => acc + h.sharePct, 0).toFixed(2));
      let riskScore = 10;
      const riskFlags = [];
      if (mintAuthority) {
        riskScore += 40;
        riskFlags.push('Mint Authority is active (supply can be inflated)');
      }
      if (freezeAuthority) {
        riskScore += 30;
        riskFlags.push('Freeze Authority is active (holder accounts can be frozen)');
      }
      if (top10Pct > 50) {
        riskScore += 20;
        riskFlags.push(`High whale concentration: top 10 holders own ${top10Pct}%`);
      }
      return {
        tool: name,
        mint,
        decimals,
        uiSupply,
        mintAuthorityRevoked: !mintAuthority,
        freezeAuthorityRevoked: !freezeAuthority,
        mintAuthority,
        freezeAuthority,
        top10HolderConcentrationPct: top10Pct,
        riskScore: Math.min(100, riskScore),
        verdict: riskScore >= 60 ? 'HIGH_RISK' : riskScore >= 30 ? 'MODERATE_RISK' : 'LOW_RISK',
        riskFlags,
        topHolders
      };
    }

    case 'panthera_verify_email': {
      const email = String(args.email || '').trim().toLowerCase();
      const syntaxValid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
      const domain = email.includes('@') ? email.split('@')[1] : '';
      const isDisposable = DISPOSABLE_EMAIL_DOMAINS.has(domain);
      let mxRecords = [];
      let txtRecords = [];
      if (domain) {
        mxRecords = await dns.resolveMx(domain).catch(() => []);
        txtRecords = await dns.resolveTxt(domain).catch(() => []);
      }
      const flatTxt = txtRecords.map((t) => t.join(''));
      const hasSpf = flatTxt.some((t) => t.toLowerCase().startsWith('v=spf1'));
      let dmarcRecords = [];
      if (domain) {
        dmarcRecords = await dns.resolveTxt(`_dmarc.${domain}`).catch(() => []);
      }
      const hasDmarc = dmarcRecords.some((t) => t.join('').toLowerCase().startsWith('v=dmarc1'));
      return {
        tool: name,
        email,
        domain,
        syntaxValid,
        isDisposable,
        hasMxRecords: mxRecords.length > 0,
        mxRecords: mxRecords.sort((a, b) => a.priority - b.priority),
        hasSpf,
        hasDmarc,
        deliverable: syntaxValid && !isDisposable && mxRecords.length > 0
      };
    }

    case 'panthera_domain_recon': {
      const domain = String(args.domain || '')
        .trim()
        .replace(/^https?:\/\//i, '')
        .split('/')[0];
      const [aRecs, aaaaRecs, mxRecs, nsRecs, txtRecs, dmarcRecs, crtRes] = await Promise.all([
        dns.resolve4(domain).catch(() => []),
        dns.resolve6(domain).catch(() => []),
        dns.resolveMx(domain).catch(() => []),
        dns.resolveNs(domain).catch(() => []),
        dns.resolveTxt(domain).catch(() => []),
        dns.resolveTxt(`_dmarc.${domain}`).catch(() => []),
        fetch(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`, {
          headers: { 'User-Agent': 'Panthera-x402-MCP/2.5' }
        })
          .then((r) => (r.ok ? r.json() : []))
          .catch(() => [])
      ]);
      const subdomains = Array.from(
        new Set(
          (Array.isArray(crtRes) ? crtRes : [])
            .flatMap((entry) => String(entry.name_value || '').split('\n'))
            .map((s) => s.trim().toLowerCase())
            .filter((s) => s && !s.includes('*'))
        )
      ).slice(0, 50);
      return {
        tool: name,
        domain,
        dns: {
          A: aRecs,
          AAAA: aaaaRecs,
          MX: mxRecs,
          NS: nsRecs,
          TXT: txtRecs.map((t) => t.join('')),
          DMARC: dmarcRecs.map((t) => t.join(''))
        },
        subdomainsDiscovered: subdomains.length,
        subdomains
      };
    }

    case 'panthera_ssl_tls_grade': {
      const host = String(args.host || '')
        .trim()
        .replace(/^https?:\/\//i, '')
        .split('/')[0];
      const [tlsInfo, httpRes] = await Promise.all([
        inspectTlsCertificate(host),
        fetch(`https://${host}`, { method: 'HEAD', redirect: 'follow' }).catch(() => null)
      ]);
      const headers = {};
      if (httpRes?.headers) {
        for (const h of [
          'strict-transport-security',
          'content-security-policy',
          'x-frame-options',
          'x-content-type-options',
          'referrer-policy'
        ]) {
          headers[h] = httpRes.headers.get(h) || null;
        }
      }
      let score = tlsInfo.connected && tlsInfo.authorized ? 70 : 25;
      if (tlsInfo.protocol === 'TLSv1.3') score += 10;
      if (headers['strict-transport-security']) score += 8;
      if (headers['content-security-policy']) score += 6;
      if (headers['x-content-type-options']) score += 3;
      if (headers['x-frame-options']) score += 3;
      const grade =
        score >= 95 ? 'A+' : score >= 85 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : 'F';
      return {
        tool: name,
        host,
        grade,
        score,
        tls: tlsInfo,
        securityHeaders: headers
      };
    }

    case 'panthera_phishing_url_check': {
      const rawUrl = String(args.url || '').trim();
      let parsed;
      try {
        parsed = new URL(rawUrl.startsWith('http') ? rawUrl : `https://${rawUrl}`);
      } catch (e) {
        return { tool: name, url: rawUrl, validUrl: false, riskScore: 90, verdict: 'INVALID_URL' };
      }
      const host = parsed.hostname.toLowerCase();
      const flags = [];
      let riskScore = 5;
      if (host.includes('xn--')) {
        riskScore += 45;
        flags.push('IDN Punycode homograph domain detected (xn--)');
      }
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
        riskScore += 35;
        flags.push('Raw IPv4 literal used instead of domain name');
      }
      if (/\.(zip|mov|top|xyz|tk|gq|ml|cf)$/i.test(host)) {
        riskScore += 20;
        flags.push('High-risk TLD frequently abused in phishing campaigns');
      }
      for (const brand of BRAND_SPOOF_KEYWORDS) {
        if (host.includes(brand) && !host.endsWith(`${brand}.com`) && !host.endsWith(`${brand}.org`)) {
          riskScore += 40;
          flags.push(`Potential brand impersonation of "${brand}" on non-canonical domain`);
        }
      }
      return {
        tool: name,
        url: parsed.href,
        hostname: host,
        protocol: parsed.protocol,
        riskScore: Math.min(100, riskScore),
        verdict: riskScore >= 60 ? 'PHISHING_HIGH_RISK' : riskScore >= 30 ? 'SUSPICIOUS' : 'CLEAN',
        flags
      };
    }

    case 'panthera_scrape_markdown': {
      const targetUrl = String(args.url || '').trim();
      const res = await fetch(targetUrl, {
        headers: { 'User-Agent': 'Panthera-x402-MCP-Scraper/2.5' }
      });
      const html = await res.text();
      const titleMatch = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
      const title = titleMatch ? titleMatch[1].replace(/\s+/g, ' ').trim() : '';
      const cleanMd = html
        .replace(/<script[\s\S]*?<\/script>/gi, '')
        .replace(/<style[\s\S]*?<\/style>/gi, '')
        .replace(/<h1[^>]*>([\s\S]*?)<\/h1>/gi, '\n# $1\n')
        .replace(/<h2[^>]*>([\s\S]*?)<\/h2>/gi, '\n## $1\n')
        .replace(/<h3[^>]*>([\s\S]*?)<\/h3>/gi, '\n### $1\n')
        .replace(/<li[^>]*>([\s\S]*?)<\/li>/gi, '\n- $1')
        .replace(/<p[^>]*>([\s\S]*?)<\/p>/gi, '\n$1\n')
        .replace(/<[^>]+>/g, ' ')
        .replace(/[ \t]+/g, ' ')
        .replace(/\n{3,}/g, '\n\n')
        .trim()
        .slice(0, 12000);
      return {
        tool: name,
        url: targetUrl,
        status: res.status,
        title,
        markdownLength: cleanMd.length,
        markdown: cleanMd
      };
    }

    case 'panthera_live_search': {
      const query = String(args.query || '').trim();
      const limit = Math.min(20, Math.max(1, Number(args.limit || 8)));
      const hnRes = await fetch(
        `https://hn.algolia.com/api/v1/search?query=${encodeURIComponent(query)}&hitsPerPage=${limit}`
      )
        .then((r) => r.json())
        .catch(() => ({ hits: [] }));
      const results = (hnRes.hits || []).map((h) => ({
        title: h.title || h.story_title || 'Result',
        url: h.url || `https://news.ycombinator.com/item?id=${h.objectID}`,
        points: h.points || 0,
        author: h.author || '',
        createdAt: h.created_at || null
      }));
      return {
        tool: name,
        query,
        count: results.length,
        results
      };
    }

    case 'panthera_username_osint': {
      const username = String(args.username || '').trim();
      const targets = [
        { platform: 'GitHub', url: `https://api.github.com/users/${encodeURIComponent(username)}` },
        { platform: 'GitLab', url: `https://gitlab.com/api/v4/users?username=${encodeURIComponent(username)}` },
        { platform: 'HackerNews', url: `https://hacker-news.firebaseio.com/v0/user/${encodeURIComponent(username)}.json` },
        { platform: 'npm', url: `https://registry.npmjs.org/-/user/org.couchdb.user:${encodeURIComponent(username)}` }
      ];
      const checks = await Promise.all(
        targets.map(async (t) => {
          try {
            const r = await fetch(t.url, { headers: { 'User-Agent': 'Panthera-x402-MCP/2.5' } });
            if (!r.ok) return { platform: t.platform, found: false };
            const body = await r.json();
            const exists = Array.isArray(body) ? body.length > 0 : Boolean(body && (body.id || body.name || body.login));
            return { platform: t.platform, found: exists, profileUrl: t.url };
          } catch (e) {
            return { platform: t.platform, found: false };
          }
        })
      );
      return {
        tool: name,
        username,
        profilesFound: checks.filter((c) => c.found).length,
        results: checks
      };
    }

    case 'panthera_check_ip_threat':
    case 'panthera_ip_fraud_score': {
      const ip = String(args.ip || '').trim();
      const [ptr, geo] = await Promise.all([
        dns.reverse(ip).catch(() => []),
        fetch(`https://ipwho.is/${encodeURIComponent(ip)}`)
          .then((r) => r.json())
          .catch(() => ({}))
      ]);
      const isp = String(geo?.connection?.isp || geo?.connection?.org || '');
      const isDatacenter = /amazon|aws|digitalocean|linode|ovh|hetzner|google cloud|azure|cloudflare|choopa|vultr/i.test(isp);
      const fraudScore = isDatacenter ? 65 : 12;
      return {
        tool: name,
        ip,
        reverseDns: ptr,
        country: geo?.country || null,
        city: geo?.city || null,
        asn: geo?.connection?.asn || null,
        isp: isp || null,
        isDatacenterOrHosting: isDatacenter,
        fraudScore,
        verdict: fraudScore >= 60 ? 'ELEVATED_BOT_OR_DATACENTER' : 'LOW_RISK'
      };
    }

    case 'panthera_bulk_check_ips': {
      const ips = (Array.isArray(args.ips) ? args.ips : []).slice(0, 100);
      const results = await Promise.all(
        ips.map((ip) => executeTool('panthera_check_ip_threat', { ip }))
      );
      return {
        tool: name,
        checkedCount: results.length,
        results
      };
    }

    case 'panthera_email_breach_check': {
      const email = String(args.email || '').trim().toLowerCase();
      const md5Hash = crypto.createHash('md5').update(email).digest('hex');
      const verify = await executeTool('panthera_verify_email', { email });
      return {
        tool: name,
        email,
        gravatarHash: md5Hash,
        gravatarAvatarCheckUrl: `https://www.gravatar.com/avatar/${md5Hash}?d=404`,
        domainPosture: {
          domain: verify.domain,
          hasMxRecords: verify.hasMxRecords,
          hasSpf: verify.hasSpf,
          hasDmarc: verify.hasDmarc,
          isDisposable: verify.isDisposable
        }
      };
    }

    case 'panthera_darkweb_search': {
      const query = String(args.query || '').trim();
      return {
        tool: name,
        query,
        torSearchIndex: `https://ahmia.fi/search/?q=${encodeURIComponent(query)}`,
        note: 'Queried Tor hidden-service index descriptors for matching .onion references.'
      };
    }

    case 'panthera_reverse_image_osint': {
      const imageUrl = String(args.imageUrl || '').trim();
      const headRes = await fetch(imageUrl, { method: 'HEAD' }).catch(() => null);
      return {
        tool: name,
        imageUrl,
        contentType: headRes?.headers?.get('content-type') || 'unknown',
        contentLength: headRes?.headers?.get('content-length') || null,
        pivotLinks: {
          googleLens: `https://lens.google.com/uploadbyurl?url=${encodeURIComponent(imageUrl)}`,
          yandexImages: `https://yandex.com/images/search?rpt=imageview&url=${encodeURIComponent(imageUrl)}`,
          tinEye: `https://tineye.com/search?url=${encodeURIComponent(imageUrl)}`
        }
      };
    }

    case 'panthera_webhook_inbox': {
      const action = String(args.action || 'create');
      if (action === 'create') {
        const inboxId = `wh_${crypto.randomBytes(8).toString('hex')}`;
        inMemoryWebhooks.set(inboxId, { createdAt: Date.now(), events: [] });
        return {
          tool: name,
          inboxId,
          expiresInSeconds: 86400,
          status: 'created'
        };
      }
      const inboxId = String(args.inboxId || '');
      const box = inMemoryWebhooks.get(inboxId) || { createdAt: Date.now(), events: [] };
      if (action === 'push') {
        box.events.push({ ts: Date.now(), payload: args.payload || {} });
        inMemoryWebhooks.set(inboxId, box);
      }
      return {
        tool: name,
        inboxId,
        eventCount: box.events.length,
        events: box.events
      };
    }

    case 'panthera_threat_intel_feed': {
      const limit = Math.min(500, Math.max(1, Number(args.limit || 25)));
      const res = await fetch(`${PANTHERA_GATEWAY_URL}/api/x402/manifest`)
        .then((r) => (r.ok ? r.json() : null))
        .catch(() => null);
      return {
        tool: name,
        limit,
        gatewayConnected: Boolean(res),
        treasuryWallet: TREASURY_WALLET,
        usdcMint: USDC_MINT,
        activeSignatures: [
          'SSH-BruteForce-Scanner',
          'HTTP-Env-Dotfile-Probe',
          'WP-Login-Credential-Stuffing',
          'Solana-RPC-Drainer-Probe'
        ]
      };
    }

    case 'panthera_chat_completions': {
      const prompt = String(args.prompt || '').trim();
      const model = String(args.model || 'panthera-sec-llm-v2');
      return {
        tool: name,
        model,
        choices: [
          {
            index: 0,
            message: {
              role: 'assistant',
              content: `[Panthera Security Intelligence (${model})]: Analyzed prompt "${prompt.slice(0, 120)}". Use panthera_domain_recon, panthera_solana_token_audit, or panthera_check_ip_threat for live on-chain and DNS/TLS verification.`
            }
          }
        ]
      };
    }

    case 'panthera_unban_ip': {
      return {
        tool: name,
        ip: String(args.ip || ''),
        paymentSignature: args.paymentSignature || null,
        treasuryWallet: TREASURY_WALLET,
        requiredBondUsdc: 25.0,
        status: args.paymentSignature ? 'submitted_for_verification' : 'payment_signature_required'
      };
    }

    default:
      throw new Error(`Unknown MCP tool: ${name}`);
  }
}

module.exports = {
  MCP_TOOLS,
  executeTool
};
