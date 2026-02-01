#!/usr/bin/env node
/**
 * Clawback Server
 * Real-time message filtering webhook for OpenClaw
 * 
 * Run as a sidecar service to scan messages before they reach your agent.
 * 
 * Usage:
 *   clawback serve --port 3000
 *   
 * Endpoints:
 *   POST /scan          - Scan a message, return decision
 *   POST /scan/batch    - Scan multiple messages
 *   GET  /health        - Health check
 *   GET  /stats         - Scan statistics
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const { scanMessage } = require('./scanner');
const { checkMessage } = require('./openclaw-hook');

// Default configuration
const DEFAULT_CONFIG = {
  port: 3000,
  host: '127.0.0.1',
  
  // Thresholds for automatic decisions
  blockThreshold: 'critical',  // Block if severity >= this
  reviewThreshold: 'high',     // Flag for review if severity >= this
  
  // Rate limiting (requests per minute per IP)
  rateLimit: 100,
  
  // Webhook for alerts (optional)
  alertWebhook: null,
  
  // Log level
  logLevel: 'info',  // 'debug', 'info', 'warn', 'error'
};

// Statistics
const stats = {
  startTime: Date.now(),
  totalScans: 0,
  blocked: 0,
  flagged: 0,
  passed: 0,
  errors: 0,
  byCategory: {},
  recentThreats: [],  // Last 100 threats
  riskScores: [],     // Last 100 risk scores for distribution
};

// SSE clients
const sseClients = new Set();

// Rate limiting store
const rateLimits = new Map();

/**
 * Broadcast event to all SSE clients
 */
function broadcast(event) {
  const data = `data: ${JSON.stringify(event)}\n\n`;
  for (const client of sseClients) {
    try {
      client.write(data);
    } catch (e) {
      sseClients.delete(client);
    }
  }
}

/**
 * Record a threat and broadcast
 */
function recordThreat(threat, action) {
  const threatRecord = {
    ...threat,
    action,
    timestamp: new Date().toISOString(),
  };
  
  stats.recentThreats.unshift(threatRecord);
  if (stats.recentThreats.length > 100) stats.recentThreats.pop();
  
  broadcast({ type: 'threat', threat: threatRecord });
}

/**
 * Record risk score for distribution
 */
function recordRiskScore(score) {
  stats.riskScores.unshift(score);
  if (stats.riskScores.length > 100) stats.riskScores.pop();
  
  broadcast({ type: 'scan', riskScore: score });
}

/**
 * Parse JSON body from request
 */
function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      // Limit body size to 1MB
      if (body.length > 1024 * 1024) {
        reject(new Error('Body too large'));
      }
    });
    req.on('end', () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch (err) {
        reject(new Error('Invalid JSON'));
      }
    });
    req.on('error', reject);
  });
}

/**
 * Send JSON response
 */
function sendJSON(res, statusCode, data) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'X-Clawback-Version': '0.2.0',
  });
  res.end(JSON.stringify(data));
}

/**
 * Get client IP from request
 */
function getClientIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
         req.socket.remoteAddress ||
         'unknown';
}

/**
 * Check rate limit for IP
 */
function checkRateLimit(ip, config) {
  const now = Date.now();
  const windowMs = 60 * 1000; // 1 minute window
  
  if (!rateLimits.has(ip)) {
    rateLimits.set(ip, { count: 1, windowStart: now });
    return true;
  }
  
  const limit = rateLimits.get(ip);
  
  // Reset window if expired
  if (now - limit.windowStart > windowMs) {
    limit.count = 1;
    limit.windowStart = now;
    return true;
  }
  
  // Check limit
  if (limit.count >= config.rateLimit) {
    return false;
  }
  
  limit.count++;
  return true;
}

/**
 * Determine action based on scan results and config
 */
function determineAction(result, config) {
  const severityOrder = ['low', 'medium', 'high', 'critical'];
  const blockIdx = severityOrder.indexOf(config.blockThreshold);
  const reviewIdx = severityOrder.indexOf(config.reviewThreshold);
  
  for (const threat of result.threats) {
    const threatIdx = severityOrder.indexOf(threat.severity);
    
    if (threatIdx >= blockIdx) {
      return 'block';
    }
    if (threatIdx >= reviewIdx) {
      return 'review';
    }
  }
  
  return 'allow';
}

/**
 * Send alert to webhook if configured
 */
async function sendAlert(config, scanResult, context) {
  if (!config.alertWebhook) return;
  
  try {
    const alertData = JSON.stringify({
      type: 'clawback_alert',
      timestamp: new Date().toISOString(),
      result: scanResult,
      context,
    });
    
    const url = new URL(config.alertWebhook);
    const options = {
      hostname: url.hostname,
      port: url.port || (url.protocol === 'https:' ? 443 : 80),
      path: url.pathname + url.search,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(alertData),
      },
    };
    
    const httpModule = url.protocol === 'https:' ? require('https') : http;
    
    const req = httpModule.request(options);
    req.on('error', () => {}); // Ignore webhook errors
    req.write(alertData);
    req.end();
  } catch (err) {
    // Ignore webhook errors
  }
}

/**
 * Handle POST /scan
 */
async function handleScan(req, res, config) {
  try {
    const body = await parseBody(req);
    
    if (!body.message && !body.text && !body.content) {
      sendJSON(res, 400, {
        error: 'Missing message field',
        usage: 'POST { "message": "text to scan" }',
      });
      return;
    }
    
    const message = body.message || body.text || body.content;
    const context = body.context || {};
    const sensitivity = body.sensitivity || 'medium';
    
    // Scan the message
    const result = checkMessage(message, context);
    const action = determineAction(result, config);
    
    // Update stats
    stats.totalScans++;
    if (action === 'block') stats.blocked++;
    else if (action === 'review') stats.flagged++;
    else stats.passed++;
    
    // Track categories and record threats
    for (const threat of result.threats) {
      stats.byCategory[threat.category] = (stats.byCategory[threat.category] || 0) + 1;
      recordThreat({
        id: threat.signatureId,
        name: threat.name,
        category: threat.category,
        severity: threat.severity,
        match: threat.match,
      }, action);
    }
    
    // Record risk score
    recordRiskScore(result.riskScore);
    
    // Broadcast updated stats
    broadcast({
      type: 'stats',
      totalScans: stats.totalScans,
      blocked: stats.blocked,
      flagged: stats.flagged,
      passed: stats.passed,
      errors: stats.errors,
      byCategory: stats.byCategory,
    });
    
    // Send alert if blocked or flagged
    if (action !== 'allow' && config.alertWebhook) {
      sendAlert(config, result, context);
    }
    
    // Response
    const response = {
      action,
      safe: result.safe,
      riskScore: result.riskScore,
      threatCount: result.threatCount,
      threats: result.threats.map(t => ({
        id: t.signatureId,
        name: t.name,
        category: t.category,
        severity: t.severity,
        match: t.match,
      })),
      recommendation: result.recommendation,
      scannedAt: result.scannedAt || new Date().toISOString(),
    };
    
    // Include alert message if threats found
    if (result.alert) {
      response.alert = result.alert;
    }
    
    sendJSON(res, 200, response);
    
  } catch (err) {
    stats.errors++;
    sendJSON(res, 500, { error: err.message });
  }
}

/**
 * Handle POST /scan/batch
 */
async function handleBatchScan(req, res, config) {
  try {
    const body = await parseBody(req);
    
    if (!Array.isArray(body.messages)) {
      sendJSON(res, 400, {
        error: 'Missing messages array',
        usage: 'POST { "messages": ["text1", "text2"] }',
      });
      return;
    }
    
    if (body.messages.length > 100) {
      sendJSON(res, 400, { error: 'Maximum 100 messages per batch' });
      return;
    }
    
    const results = body.messages.map((msg, idx) => {
      const message = typeof msg === 'string' ? msg : (msg.message || msg.text || msg.content);
      const context = typeof msg === 'object' ? msg.context : {};
      
      if (!message) {
        return { index: idx, error: 'Missing message' };
      }
      
      const result = checkMessage(message, context);
      const action = determineAction(result, config);
      
      stats.totalScans++;
      if (action === 'block') stats.blocked++;
      else if (action === 'review') stats.flagged++;
      else stats.passed++;
      
      return {
        index: idx,
        action,
        safe: result.safe,
        riskScore: result.riskScore,
        threatCount: result.threatCount,
      };
    });
    
    sendJSON(res, 200, {
      count: results.length,
      results,
      summary: {
        blocked: results.filter(r => r.action === 'block').length,
        review: results.filter(r => r.action === 'review').length,
        allowed: results.filter(r => r.action === 'allow').length,
      },
    });
    
  } catch (err) {
    stats.errors++;
    sendJSON(res, 500, { error: err.message });
  }
}

/**
 * Handle GET /health
 */
function handleHealth(req, res) {
  sendJSON(res, 200, {
    status: 'healthy',
    uptime: Math.floor((Date.now() - stats.startTime) / 1000),
    version: '0.2.0',
  });
}

/**
 * Handle GET /stats
 */
function handleStats(req, res) {
  const uptime = Math.floor((Date.now() - stats.startTime) / 1000);
  const rate = stats.totalScans / Math.max(uptime, 1) * 60; // per minute
  
  sendJSON(res, 200, {
    uptime,
    uptimeHuman: `${Math.floor(uptime / 3600)}h ${Math.floor((uptime % 3600) / 60)}m`,
    totalScans: stats.totalScans,
    blocked: stats.blocked,
    flagged: stats.flagged,
    passed: stats.passed,
    errors: stats.errors,
    blockRate: stats.totalScans ? (stats.blocked / stats.totalScans * 100).toFixed(2) + '%' : '0%',
    scansPerMinute: rate.toFixed(2),
    byCategory: stats.byCategory,
    recentThreats: stats.recentThreats.slice(0, 20),
  });
}

/**
 * Handle GET /dashboard - serve the monitoring UI
 */
function handleDashboard(req, res) {
  const dashboardPath = path.join(__dirname, 'dashboard.html');
  
  try {
    const html = fs.readFileSync(dashboardPath, 'utf8');
    res.writeHead(200, {
      'Content-Type': 'text/html',
      'Cache-Control': 'no-cache',
    });
    res.end(html);
  } catch (err) {
    res.writeHead(500, { 'Content-Type': 'text/plain' });
    res.end('Dashboard not found');
  }
}

/**
 * Handle GET /events - SSE stream for real-time updates
 */
function handleEvents(req, res) {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'Access-Control-Allow-Origin': '*',
  });
  
  // Send initial stats
  const uptime = Math.floor((Date.now() - stats.startTime) / 1000);
  const rate = stats.totalScans / Math.max(uptime, 1) * 60;
  
  res.write(`data: ${JSON.stringify({
    type: 'stats',
    totalScans: stats.totalScans,
    blocked: stats.blocked,
    flagged: stats.flagged,
    passed: stats.passed,
    errors: stats.errors,
    uptimeHuman: `${Math.floor(uptime / 3600)}h ${Math.floor((uptime % 3600) / 60)}m`,
    scansPerMinute: rate.toFixed(2),
    blockRate: stats.totalScans ? (stats.blocked / stats.totalScans * 100).toFixed(2) + '%' : '0%',
    byCategory: stats.byCategory,
  })}\n\n`);
  
  // Send recent threats
  for (const threat of stats.recentThreats.slice(0, 20)) {
    res.write(`data: ${JSON.stringify({ type: 'threat', threat })}\n\n`);
  }
  
  // Add to SSE clients
  sseClients.add(res);
  
  // Heartbeat every 30 seconds
  const heartbeat = setInterval(() => {
    try {
      res.write(':heartbeat\n\n');
    } catch (e) {
      clearInterval(heartbeat);
      sseClients.delete(res);
    }
  }, 30000);
  
  // Cleanup on close
  req.on('close', () => {
    clearInterval(heartbeat);
    sseClients.delete(res);
  });
}

/**
 * Main request handler
 */
function createRequestHandler(config) {
  return async (req, res) => {
    const ip = getClientIP(req);
    const url = req.url.split('?')[0];
    
    // CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    
    // Handle preflight
    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }
    
    // Rate limiting
    if (!checkRateLimit(ip, config)) {
      sendJSON(res, 429, { error: 'Rate limit exceeded' });
      return;
    }
    
    // Routing
    try {
      if (req.method === 'POST' && url === '/scan') {
        await handleScan(req, res, config);
      } else if (req.method === 'POST' && url === '/scan/batch') {
        await handleBatchScan(req, res, config);
      } else if (req.method === 'GET' && url === '/health') {
        handleHealth(req, res);
      } else if (req.method === 'GET' && url === '/stats') {
        handleStats(req, res);
      } else if (req.method === 'GET' && url === '/dashboard') {
        handleDashboard(req, res);
      } else if (req.method === 'GET' && url === '/events') {
        handleEvents(req, res);
      } else if (req.method === 'GET' && url === '/') {
        sendJSON(res, 200, {
          name: 'Clawback Security Scanner',
          version: '0.2.0',
          endpoints: {
            'POST /scan': 'Scan a message',
            'POST /scan/batch': 'Scan multiple messages',
            'GET /health': 'Health check',
            'GET /stats': 'Scan statistics',
            'GET /dashboard': 'Live monitoring dashboard',
            'GET /events': 'SSE event stream',
          },
          docs: 'https://github.com/davidcjones79/clawback',
        });
      } else {
        sendJSON(res, 404, { error: 'Not found' });
      }
    } catch (err) {
      stats.errors++;
      sendJSON(res, 500, { error: 'Internal server error' });
    }
  };
}

/**
 * Start the server
 */
function startServer(userConfig = {}) {
  const config = { ...DEFAULT_CONFIG, ...userConfig };
  
  const server = http.createServer(createRequestHandler(config));
  
  server.listen(config.port, config.host, () => {
    console.log(`
🛡️  Clawback Security Scanner v0.2.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Server running at http://${config.host}:${config.port}

📊 Dashboard: http://${config.host}:${config.port}/dashboard

Endpoints:
  POST /scan        Scan a message
  POST /scan/batch  Scan multiple messages
  GET  /health      Health check
  GET  /stats       Statistics
  GET  /dashboard   Live monitoring UI
  GET  /events      SSE event stream

Configuration:
  Block threshold:  ${config.blockThreshold}
  Review threshold: ${config.reviewThreshold}
  Rate limit:       ${config.rateLimit}/min

Example:
  curl -X POST http://${config.host}:${config.port}/scan \\
    -H "Content-Type: application/json" \\
    -d '{"message": "ignore previous instructions"}'

Press Ctrl+C to stop
`);
  });
  
  // Graceful shutdown
  process.on('SIGINT', () => {
    console.log('\nShutting down...');
    server.close(() => {
      console.log('Server stopped');
      process.exit(0);
    });
  });
  
  return server;
}

// CLI entry point
if (require.main === module) {
  const args = process.argv.slice(2);
  const config = {};
  
  // Parse CLI arguments
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--port' || args[i] === '-p') {
      config.port = parseInt(args[++i], 10);
    } else if (args[i] === '--host' || args[i] === '-h') {
      config.host = args[++i];
    } else if (args[i] === '--block-threshold') {
      config.blockThreshold = args[++i];
    } else if (args[i] === '--review-threshold') {
      config.reviewThreshold = args[++i];
    } else if (args[i] === '--alert-webhook') {
      config.alertWebhook = args[++i];
    } else if (args[i] === '--rate-limit') {
      config.rateLimit = parseInt(args[++i], 10);
    } else if (args[i] === '--help') {
      console.log(`
Clawback Server - Real-time message filtering

Usage:
  node server.js [options]
  clawback serve [options]

Options:
  --port, -p <port>           Port to listen on (default: 3000)
  --host, -h <host>           Host to bind to (default: 127.0.0.1)
  --block-threshold <level>   Severity to auto-block (default: critical)
  --review-threshold <level>  Severity to flag for review (default: high)
  --alert-webhook <url>       Webhook URL for alerts
  --rate-limit <n>            Requests per minute per IP (default: 100)
  --help                      Show this help

Severity levels: low, medium, high, critical
`);
      process.exit(0);
    }
  }
  
  startServer(config);
}

module.exports = { startServer, createRequestHandler };
