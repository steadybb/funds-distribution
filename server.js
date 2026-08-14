require('dotenv').config({
    path: require('path').join(__dirname, '.env'),
    override: true
});

const express = require('express');
const helmet = require('helmet');
const crypto = require('crypto');
const dns = require('dns');
const net = require('net');
const fetch = require('node-fetch');
const fs = require('fs');
const NodeCache = require('node-cache');
const pino = require('pino');
const { join } = require('path');
const compression = require('compression');
const { v4: uuidv4 } = require('uuid');
const sqlite3 = require('sqlite3').verbose();

// ====================== UA-PARSER (optional) ======================
let UAParser = null;
try {
    UAParser = require('ua-parser-js');
} catch (e) {
    // UA-Parser optional - fallback to basic parsing
    UAParser = function(ua) {
        return {
            getResult: () => ({
                device: { type: 'unknown', vendor: 'unknown', model: 'unknown' },
                os: { name: 'unknown', version: 'unknown' },
                browser: { name: 'unknown', version: 'unknown' },
                engine: { name: 'unknown', version: 'unknown' },
                cpu: { architecture: 'unknown' }
            })
        };
    };
}

// ====================== TELEGRAM BOT IMPORTS ======================
let TelegramBot = null;
try {
    TelegramBot = require('node-telegram-bot-api');
} catch (e) {
    // Telegram bot optional
}

const app = express();
app.set('trust proxy', false);
process.on('unhandledRejection', (err) => {
    logger.error({ error: err && err.message ? err.message : String(err), stack: err && err.stack ? err.stack : undefined }, 'unhandled_rejection');
});

// ====================== CONFIGURATION ======================
const PORT = process.env.PORT || 10000;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const DB_PATH = process.env.DB_PATH || join(process.cwd(), 'redirects.db');
const DB_JSON_PATH = process.env.DB_PATH_JSON || join(process.cwd(), 'redirects.json');
const GEO_API_URL = process.env.GEO_API_URL || 'https://ipinfo.io/{ip}/country';
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || '';
const MAX_RATE_LIMIT_ENTRIES = Number(process.env.MAX_RATE_LIMIT_ENTRIES || 10000);
const MAX_BOT_BLOCK_ROWS = Number(process.env.MAX_BOT_BLOCK_ROWS || 5000);
const SESSION_COOKIE_NAME = '_session';
const SESSION_TTL_MS = 24 * 60 * 60 * 1000;
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const BOT_ALERT_COOLDOWN_MS = 60 * 1000;
const MAX_BOT_ALERT_KEYS = 10000;
const MAX_CHALLENGES = 10000;
const MAX_RECENT_UPDATES = 1000;
const DNS_CACHE_TTL = 300;
const DNS_LOOKUP_TIMEOUT_MS = 2000;
const MAX_CONCURRENT_DNS_LOOKUPS = 8;
const DNS_SEMAPHORE_TIMEOUT_MS = 5000;
const CREATION_LIMIT_PER_IP = 20;
const CREATION_WINDOW_MS = 3600000;
const MAX_TOTAL_LINKS = 100000;
const MAX_LINK_CREATION_ENTRIES = 10000;
const SOLVED_SESSION_TTL = 300000;
const MAX_EXPIRY_SECONDS = 315360000;
const ENABLE_FINGERPRINTING = process.env.ENABLE_FINGERPRINTING !== 'false';
const FINGERPRINT_SALT = process.env.FINGERPRINT_SALT || crypto.randomBytes(16).toString('hex');
const FINGERPRINT_RATE_LIMIT = 30; // per minute
const MAX_FP_FIELD = 256;
const RETENTION_DAYS = Number(process.env.RETENTION_DAYS || 30);
const MAX_FINGERPRINT_ROWS = Number(process.env.MAX_FINGERPRINT_ROWS || 200000);

// ====================== TELEGRAM CONFIGURATION ======================
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID;
const TELEGRAM_WEBHOOK_URL = process.env.TELEGRAM_WEBHOOK_URL;
const TELEGRAM_WEBHOOK_SECRET = process.env.TELEGRAM_WEBHOOK_SECRET || '';
const ALLOWED_TELEGRAM_CHAT_IDS = new Set(
    (process.env.ALLOWED_TELEGRAM_CHAT_IDS || TELEGRAM_CHAT_ID || '')
        .split(',').map(v => String(v).trim()).filter(Boolean)
);
const ENABLE_TELEGRAM = process.env.ENABLE_TELEGRAM !== 'false' && TELEGRAM_BOT_TOKEN && TELEGRAM_CHAT_ID && TelegramBot;

if (TELEGRAM_WEBHOOK_URL && !TELEGRAM_WEBHOOK_SECRET && ENABLE_TELEGRAM) {
    throw new Error('TELEGRAM_WEBHOOK_SECRET is required when TELEGRAM_WEBHOOK_URL is set');
}

// ====================== BOT DETECTION PATTERNS ======================
const BOT_PATTERNS = {
    headless: /headless|phantom|puppeteer|playwright|selenium|webdriver|chrome-headless/i,
    crawler: /googlebot|bingbot|baiduspider|yandexbot|duckduckbot|slurp|facebookexternalhit|twitterbot|linkedinbot/i,
    ai_crawler: /gptbot|chatgpt|openai|claudebot|anthropic|perplexity|gemini|bard|deepseek|claude|llama|mistral/i,
    security_scanner: /zgrab|masscan|nmap|nessus|openvas|acunetix|burp|sqlmap|nikto|w3af|zap|gobuster|ffuf/i,
    http_library: /python|requests|urllib|httpx|aiohttp|curl|wget|java|okhttp|node|go-http|ruby|php/i,
    email_scanner: /outlook|exchange|microsoft|office365|proofpoint|mimecast|barracuda|sophos/i,
};

const DATACENTER_PREFIXES = {
    '52.84.': 'AWS CloudFront',
    '13.32.': 'AWS',
    '34.64.': 'Google Cloud',
    '35.184.': 'Google Cloud',
    '20.38.': 'Azure',
    '52.136.': 'Azure',
    '138.68.': 'DigitalOcean',
    '104.16.': 'CloudFlare',
    '172.64.': 'CloudFlare',
};

const DATACENTER_IPV4_MAPPED = {
    '::ffff:52.84.': 'AWS CloudFront',
    '::ffff:13.32.': 'AWS',
    '::ffff:34.64.': 'Google Cloud',
    '::ffff:35.184.': 'Google Cloud',
    '::ffff:20.38.': 'Azure',
    '::ffff:52.136.': 'Azure',
    '::ffff:138.68.': 'DigitalOcean',
    '::ffff:104.16.': 'CloudFlare',
    '::ffff:172.64.': 'CloudFlare',
};

const TRUSTED_PROXY_CIDRS = (process.env.TRUSTED_PROXY_CIDRS || '127.0.0.1/32').split(',').map(v => v.trim()).filter(Boolean);

const BOT_URLS = [
    'https://www.microsoft.com',
    'https://www.apple.com',
    'https://www.amazon.com',
    'https://www.google.com',
    'https://www.facebook.com',
    'https://www.twitter.com',
    'https://www.instagram.com',
    'https://www.linkedin.com',
    'https://www.youtube.com',
    'https://www.netflix.com',
    'https://www.spotify.com',
    'https://www.slack.com',
    'https://www.dropbox.com',
    'https://www.zoom.us',
    'https://www.adobe.com',
    'https://www.salesforce.com',
    'https://www.oracle.com',
    'https://www.ibm.com',
    'https://www.cisco.com',
    'https://www.intel.com',
    'https://en.wikipedia.org/wiki/Main_Page',
    'https://www.bbc.com',
    'https://www.cnn.com',
    'https://www.nytimes.com',
    'https://www.wsj.com',
    'https://www.reuters.com',
    'https://www.bloomberg.com',
    'https://www.economist.com',
    'https://www.theguardian.com',
    'https://www.washingtonpost.com',
    'https://www.techcrunch.com',
    'https://www.theverge.com',
    'https://www.wired.com',
    'https://arstechnica.com',
    'https://www.wikipedia.org',
    'https://www.britannica.com',
    'https://www.stackoverflow.com',
    'https://www.github.com',
    'https://www.gitlab.com',
    'https://www.atlassian.com',
    'https://www.docker.com',
    'https://www.kubernetes.io',
    'https://www.python.org',
    'https://www.nodejs.org',
    'https://www.whitehouse.gov',
    'https://www.un.org',
    'https://www.who.int',
    'https://www.nasa.gov',
    'https://www.esa.int',
    'https://www.icann.org',
    'https://www.quora.com',
    'https://www.reddit.com',
    'https://www.medium.com',
    'https://www.twitch.tv',
    'https://www.discord.com',
    'https://www.tiktok.com',
    'https://www.snapchat.com',
    'https://www.pinterest.com',
    'https://www.tumblr.com',
];

// ====================== LOGGING ======================
const logFile = process.env.LOG_FILE || 'clicks.log';
const logToConsole = process.env.LOG_TO_CONSOLE !== 'false';
const logger = logToConsole
    ? pino({ level: 'info' }, pino.transport({
        target: 'pino-pretty',
        options: { colorize: true }
    }))
    : pino({ level: 'info' }, pino.destination(join(process.cwd(), logFile)));

// ====================== SQLITE DATABASE ======================
function parseExpirySeconds(value) {
    if (value === undefined || value === null || value === '') return null;
    const parsed = Number(value);
    if (!Number.isFinite(parsed) || parsed <= 0) return null;
    return Math.min(parsed, MAX_EXPIRY_SECONDS);
}

class RedirectDatabase {
    constructor(dbPath) {
        this.dbPath = dbPath;
        this.db = null;
        this.init();
    }

    init() {
        this.db = new sqlite3.Database(this.dbPath, { timeout: 5000 });
        
        // Enable WAL mode for better concurrency
        this.db.run('PRAGMA journal_mode=WAL');
        this.db.run('PRAGMA synchronous=NORMAL');
        
        this.db.run(`
            CREATE TABLE IF NOT EXISTS redirects (
                code TEXT PRIMARY KEY,
                target_url TEXT NOT NULL,
                created_at TEXT NOT NULL,
                clicks INTEGER DEFAULT 0,
                unique_visitors INTEGER DEFAULT 0,
                last_clicked TEXT,
                expires_at TEXT,
                campaign_id TEXT
            )
        `);

        this.db.run(`
            CREATE TABLE IF NOT EXISTS bot_blocks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                user_agent TEXT,
                bot_score REAL,
                bot_confidence REAL,
                bot_verdict TEXT,
                bot_signals TEXT,
                code TEXT,
                timestamp TEXT
            )
        `);

        this.db.run(`
            CREATE TABLE IF NOT EXISTS visitors (
                code TEXT,
                visitor_id TEXT,
                first_seen TEXT,
                last_seen TEXT,
                PRIMARY KEY (code, visitor_id)
            )
        `);

        this.db.run(`
            CREATE TABLE IF NOT EXISTS device_fingerprints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fingerprint_id TEXT UNIQUE,
                code TEXT,
                ip TEXT,
                user_agent TEXT,
                device_type TEXT,
                device_brand TEXT,
                device_model TEXT,
                os_name TEXT,
                os_version TEXT,
                browser_name TEXT,
                browser_version TEXT,
                screen_resolution TEXT,
                color_depth INTEGER,
                timezone TEXT,
                language TEXT,
                platform TEXT,
                hardware_concurrency INTEGER,
                device_memory REAL,
                webgl_vendor TEXT,
                webgl_renderer TEXT,
                audio_fingerprint TEXT,
                canvas_fingerprint TEXT,
                fonts_fingerprint TEXT,
                is_bot BOOLEAN DEFAULT 0,
                bot_confidence REAL,
                first_seen TEXT,
                last_seen TEXT,
                visit_count INTEGER DEFAULT 1
            )
        `);

        this.db.run(`
            CREATE TABLE IF NOT EXISTS click_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code TEXT,
                fingerprint_id TEXT,
                ip TEXT,
                country TEXT,
                user_agent TEXT,
                referrer TEXT,
                timestamp TEXT,
                bot_score REAL,
                bot_verdict TEXT,
                device_type TEXT,
                os_name TEXT,
                browser_name TEXT
            )
        `);

        this.db.run(`CREATE INDEX IF NOT EXISTS idx_bot_blocks_timestamp ON bot_blocks(timestamp DESC)`);
        this.db.run(`CREATE INDEX IF NOT EXISTS idx_redirects_expires_at ON redirects(expires_at)`);
        this.db.run(`CREATE INDEX IF NOT EXISTS idx_fingerprint_id ON device_fingerprints(fingerprint_id)`);
        this.db.run(`CREATE INDEX IF NOT EXISTS idx_click_events_code ON click_events(code)`);
        this.db.run(`CREATE INDEX IF NOT EXISTS idx_click_events_timestamp ON click_events(timestamp)`);
        this.db.run(`CREATE INDEX IF NOT EXISTS idx_device_fingerprints_last_seen ON device_fingerprints(last_seen)`);
    }

    async getRedirect(code) {
        return new Promise((resolve, reject) => {
            this.db.get(
                'SELECT * FROM redirects WHERE code = ?',
                [code],
                (err, row) => {
                    if (err) reject(err);
                    else resolve(row);
                }
            );
        });
    }

    async getRedirectsExpired(now) {
        return new Promise((resolve, reject) => {
            this.db.all(
                'SELECT code FROM redirects WHERE expires_at IS NOT NULL AND expires_at < ?',
                [now.toISOString()],
                (err, rows) => {
                    if (err) reject(err);
                    else resolve(rows.map(r => r.code));
                }
            );
        });
    }

    async saveRedirect(code, targetUrl, expiresAt = null, campaignId = '') {
        return new Promise((resolve, reject) => {
            this.db.run(
                `INSERT OR REPLACE INTO redirects 
                 (code, target_url, created_at, expires_at, campaign_id) 
                 VALUES (?, ?, ?, ?, ?)`,
                [code, targetUrl, new Date().toISOString(), expiresAt, campaignId],
                (err) => {
                    if (err) reject(err);
                    else resolve();
                }
            );
        });
    }

    async incrementClicks(code) {
        return new Promise((resolve, reject) => {
            this.db.run(
                `UPDATE redirects 
                 SET clicks = clicks + 1, last_clicked = ? 
                 WHERE code = ?`,
                [new Date().toISOString(), code],
                (err) => {
                    if (err) reject(err);
                    else resolve();
                }
            );
        });
    }

    async addVisitor(code, visitorId) {
        return new Promise((resolve, reject) => {
            this.db.run(
                `INSERT OR IGNORE INTO visitors (code, visitor_id, first_seen, last_seen) 
                 VALUES (?, ?, ?, ?)`,
                [code, visitorId, new Date().toISOString(), new Date().toISOString()],
                (err) => {
                    if (err) reject(err);
                    else {
                        this.db.get(
                            'SELECT COUNT(*) AS count FROM visitors WHERE code = ?',
                            [code],
                            (err, row) => {
                                if (err) reject(err);
                                else {
                                    this.db.run(
                                        'UPDATE redirects SET unique_visitors = ? WHERE code = ?',
                                        [row.count, code],
                                        (err) => {
                                            if (err) reject(err);
                                            else resolve();
                                        }
                                    );
                                }
                            }
                        );
                    }
                }
            );
        });
    }

    async hasVisitor(code, visitorId) {
        return new Promise((resolve, reject) => {
            this.db.get(
                'SELECT 1 FROM visitors WHERE code = ? AND visitor_id = ?',
                [code, visitorId],
                (err, row) => {
                    if (err) reject(err);
                    else resolve(!!row);
                }
            );
        });
    }

    async logBotBlock(ip, userAgent, sig, code = null) {
        return new Promise((resolve, reject) => {
            this.db.run(
                `INSERT INTO bot_blocks 
                 (ip, user_agent, bot_score, bot_confidence, bot_verdict, bot_signals, code, timestamp) 
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
                [ip, userAgent, sig.score, sig.confidence, sig.verdict, 
                 JSON.stringify(sig.signals), code, new Date().toISOString()],
                async (err) => {
                    if (err) {
                        reject(err);
                        return;
                    }
                    try {
                        await this.pruneBotBlocks();
                        resolve();
                    } catch (e) {
                        reject(e);
                    }
                }
            );
        });
    }

    async pruneBotBlocks(limit = MAX_BOT_BLOCK_ROWS) {
        return new Promise((resolve, reject) => {
            this.db.run(
                `DELETE FROM bot_blocks
                 WHERE id NOT IN (
                     SELECT id FROM bot_blocks
                     ORDER BY timestamp DESC
                     LIMIT ?
                 )`,
                [limit],
                (err) => err ? reject(err) : resolve()
            );
        });
    }

    async getRecentBotBlocks(limit = 10) {
        return new Promise((resolve, reject) => {
            this.db.all(
                `SELECT code, bot_verdict as verdict, bot_score as score, 
                        ip, timestamp 
                 FROM bot_blocks 
                 ORDER BY timestamp DESC 
                 LIMIT ?`,
                [limit],
                (err, rows) => {
                    if (err) reject(err);
                    else resolve(rows || []);
                }
            );
        });
    }

    async getAllLinks(limit = 20) {
        return new Promise((resolve, reject) => {
            this.db.all(
                'SELECT code, target_url, clicks, created_at FROM redirects ORDER BY created_at DESC LIMIT ?',
                [limit],
                (err, rows) => {
                    if (err) reject(err);
                    else resolve(rows || []);
                }
            );
        });
    }

    async deleteLink(code) {
        return new Promise((resolve, reject) => {
            this.db.run('DELETE FROM redirects WHERE code = ?', [code], (err) => {
                if (err) reject(err);
                else {
                    this.db.run('DELETE FROM visitors WHERE code = ?', [code], (err) => {
                        if (err) reject(err);
                        else resolve();
                    });
                }
            });
        });
    }

    async getStats() {
        return new Promise((resolve, reject) => {
            const queries = [
                'SELECT COUNT(*) AS count FROM redirects',
                'SELECT SUM(clicks) AS total FROM redirects',
                'SELECT COUNT(*) AS count FROM bot_blocks WHERE bot_verdict = "block"',
                'SELECT COUNT(*) AS count FROM bot_blocks WHERE bot_verdict = "challenge"',
                'SELECT COUNT(*) AS count FROM bot_blocks WHERE bot_verdict = "decoy"'
            ];
            
            Promise.all(queries.map(q => 
                new Promise((res, rej) => {
                    this.db.get(q, (err, row) => {
                        if (err) rej(err);
                        else res(row);
                    });
                })
            )).then(results => {
                const keys = ['redirects', 'total_clicks', 'blocks', 'challenges', 'decoys'];
                const stats = {};
                results.forEach((row, i) => {
                    stats[keys[i]] = row.count || row.total || 0;
                });
                resolve(stats);
            }).catch(reject);
        });
    }

    // Fingerprint cleanup methods
    async pruneFingerprints(cutoff) {
        return new Promise((resolve, reject) => {
            this.db.run(
                'DELETE FROM device_fingerprints WHERE last_seen < ?',
                [cutoff],
                (err) => {
                    if (err) reject(err);
                    else {
                        // Hard cap
                        this.db.run(
                            `DELETE FROM device_fingerprints WHERE id NOT IN
                             (SELECT id FROM device_fingerprints ORDER BY last_seen DESC LIMIT ?)`,
                            [MAX_FINGERPRINT_ROWS],
                            (err) => {
                                if (err) reject(err);
                                else resolve();
                            }
                        );
                    }
                }
            );
        });
    }

    async pruneClickEvents(cutoff) {
        return new Promise((resolve, reject) => {
            this.db.run(
                'DELETE FROM click_events WHERE timestamp < ?',
                [cutoff],
                (err) => {
                    if (err) reject(err);
                    else resolve();
                }
            );
        });
    }

    close() {
        if (this.db) this.db.close();
    }
}

// ====================== JSON STORE ======================
let persistedStore = { links: {}, visitors: {} };

try {
    if (fs.existsSync(DB_JSON_PATH)) {
        persistedStore = JSON.parse(fs.readFileSync(DB_JSON_PATH, 'utf8')) || persistedStore;
        // Validate existing JSON entries at startup
        setTimeout(() => validateJsonStoreEntries(), 1000);
    }
} catch (e) {
    logger.warn({ error: e.message }, 'json_db_load_failed');
}

function validateJsonStoreEntries() {
    let modified = false;
    const entries = Object.entries(persistedStore.links);
    
    for (const [code, data] of entries) {
        const url = data.originalUrl;
        if (url) {
            // Remove invalid entries
            isAllowedTarget(url).then(allowed => {
                if (!allowed) {
                    logger.warn({ code, url }, 'legacy_json_invalid_target_deleted');
                    delete persistedStore.links[code];
                    delete persistedStore.visitors[code];
                    modified = true;
                }
            }).catch(() => {
                logger.warn({ code, url }, 'legacy_json_check_error_deleted');
                delete persistedStore.links[code];
                delete persistedStore.visitors[code];
                modified = true;
            });
        }
    }
    
    if (modified) {
        persistStore();
    }
}

function persistStore() {
    try {
        fs.writeFileSync(DB_JSON_PATH, JSON.stringify(persistedStore, null, 2), 'utf8');
    } catch (e) {
        logger.error({ error: e.message }, 'json_db_save_failed');
    }
}

function getLink(code) {
    return persistedStore.links[code] || null;
}

function saveLink(code, data) {
    persistedStore.links[code] = data;
    persistStore();
}

function deleteLink(code) {
    delete persistedStore.links[code];
    delete persistedStore.visitors[code];
    persistStore();
}

function hasVisitor(code, visitorId) {
    return Array.isArray(persistedStore.visitors[code]) && persistedStore.visitors[code].includes(visitorId);
}

function addVisitor(code, visitorId) {
    if (!Array.isArray(persistedStore.visitors[code])) {
        persistedStore.visitors[code] = [];
    }
    if (!persistedStore.visitors[code].includes(visitorId)) {
        persistedStore.visitors[code].push(visitorId);
        persistStore();
    }
}

// ====================== CACHES ======================
const geoCache = new NodeCache({ stdTTL: 3600, checkperiod: 120 });
const responseCache = new NodeCache({ stdTTL: 300, checkperiod: 60 });
const rateLimitStore = new Map();
const linkCreationRate = new Map();
const dnsCache = new NodeCache({ stdTTL: DNS_CACHE_TTL, checkperiod: 60 });
const botAlertCooldowns = new Map();
const recentUpdateIds = new Set();
const solvedSessions = new Map();
const fingerprintCache = new NodeCache({ stdTTL: 3600, checkperiod: 120 });
const fingerprintRateLimit = new Map();

// ====================== PERIODIC CLEANUP ======================
setInterval(() => {
    const now = Date.now();
    
    for (const [k, e] of linkCreationRate) {
        if (now - e.windowStart > CREATION_WINDOW_MS) {
            linkCreationRate.delete(k);
        }
    }
    if (linkCreationRate.size > MAX_LINK_CREATION_ENTRIES) {
        const excess = linkCreationRate.size - MAX_LINK_CREATION_ENTRIES;
        let i = 0;
        for (const k of linkCreationRate.keys()) {
            if (i++ >= excess) break;
            linkCreationRate.delete(k);
        }
    }
    
    for (const [id, data] of solvedSessions) {
        if (now - data.solvedAt > SOLVED_SESSION_TTL) {
            solvedSessions.delete(id);
        }
    }
    
    if (recentUpdateIds.size > MAX_RECENT_UPDATES) {
        const toDelete = recentUpdateIds.size - MAX_RECENT_UPDATES;
        const iterator = recentUpdateIds.values();
        for (let i = 0; i < toDelete; i++) {
            recentUpdateIds.delete(iterator.next().value);
        }
    }
    
    // Clean bot alert cooldowns (expiry-based)
    for (const [key, expiry] of botAlertCooldowns) {
        if (expiry <= now) {
            botAlertCooldowns.delete(key);
        }
    }
    if (botAlertCooldowns.size > MAX_BOT_ALERT_KEYS) {
        const toEvict = Math.ceil(MAX_BOT_ALERT_KEYS * 0.1);
        let i = 0;
        for (const k of botAlertCooldowns.keys()) {
            if (i++ >= toEvict) break;
            botAlertCooldowns.delete(k);
        }
    }

    // Clean fingerprint rate limits
    for (const [key, entry] of fingerprintRateLimit) {
        if (now - entry.windowStart > 60000) {
            fingerprintRateLimit.delete(key);
        }
    }
    if (fingerprintRateLimit.size > 10000) {
        const toDelete = fingerprintRateLimit.size - 10000;
        const keys = Array.from(fingerprintRateLimit.keys()).slice(0, toDelete);
        for (const key of keys) {
            fingerprintRateLimit.delete(key);
        }
    }

    // Data retention for fingerprints and click events
    const cutoff = new Date(Date.now() - RETENTION_DAYS * 24 * 3600 * 1000).toISOString();
    db.pruneFingerprints(cutoff).catch(err => {
        logger.error({ error: err.message }, 'fingerprint_retention_failed');
    });
    db.pruneClickEvents(cutoff).catch(err => {
        logger.error({ error: err.message }, 'click_events_retention_failed');
    });
}, 3600000);

// ====================== TELEGRAM BOT SETUP ======================
let telegramBot = null;

if (ENABLE_TELEGRAM) {
    telegramBot = new TelegramBot(TELEGRAM_BOT_TOKEN);
    
    if (TELEGRAM_WEBHOOK_URL) {
        const webhookOptions = TELEGRAM_WEBHOOK_SECRET ? { secret_token: TELEGRAM_WEBHOOK_SECRET } : {};
        telegramBot.setWebHook(TELEGRAM_WEBHOOK_URL, webhookOptions).then(() => {
            logger.info('Telegram webhook set successfully');
        }).catch(err => {
            logger.error({ error: err.message }, 'Failed to set Telegram webhook');
        });
    }
    
    const commands = [
        { command: 'start', description: 'Start the bot' },
        { command: 'help', description: 'Show help message' },
        { command: 'stats', description: 'View service statistics' },
        { command: 'recent', description: 'Show recent bot blocks' },
        { command: 'ping', description: 'Check if service is alive' }
    ];
    
    if (ENABLE_FINGERPRINTING) {
        commands.push({ command: 'fingerprints', description: 'Show device fingerprinting stats' });
    }
    
    telegramBot.setMyCommands(commands).catch(err => {
        logger.error({ error: err.message }, 'Failed to set Telegram commands');
    });
    
    setTimeout(() => {
        sendTelegramMessage(`
🚀 *Redirect Service Started*
📊 *Version:* 4.7
🛡️ *Bot Detection:* Active
🔍 *Fingerprinting:* ${ENABLE_FINGERPRINTING ? 'Enabled' : 'Disabled'}
📅 *Time:* ${new Date().toISOString()}
🔗 *Base URL:* ${BASE_URL}
        `);
    }, 2000);
}

// ====================== TELEGRAM HELPER FUNCTIONS ======================
function sendTelegramMessage(message, parseMode = 'Markdown', extra = {}) {
    if (!ENABLE_TELEGRAM || !telegramBot) return Promise.resolve(false);
    
    return telegramBot.sendMessage(TELEGRAM_CHAT_ID, message, { 
        parseMode: parseMode,
        disable_web_page_preview: true,
        ...extra
    }).catch(err => {
        logger.error({ error: err.message }, 'Failed to send Telegram message');
        return false;
    });
}

function getInlineKeyboard() {
    const buttons = [
        [
            { text: '📊 Stats', callback_data: 'stats' },
            { text: '🚫 Recent Blocks', callback_data: 'recent_blocks' }
        ]
    ];
    
    if (ENABLE_FINGERPRINTING) {
        buttons.push([
            { text: '🔍 Fingerprints', callback_data: 'fingerprints' }
        ]);
    }
    
    buttons.push([
        { text: 'ℹ️ Help', callback_data: 'help' }
    ]);
    
    return { reply_markup: { inline_keyboard: buttons } };
}

function formatTelegramHelpMessage() {
    let msg = `
🤖 *Redirect Service Bot v4.7*

Welcome! This bot helps you monitor the redirect service and check its health.

*Available commands:*
/start - Show the welcome message and usage guide
/help - Show this help message
/stats - View redirect and bot activity stats
/recent - Show recent blocked bot attempts
/ping - Confirm the service is online`;

    if (ENABLE_FINGERPRINTING) {
        msg += `\n/fingerprints - Show device fingerprinting stats`;
    }

    msg += `

*Features:*
• Real-time bot detection alerts
• Device fingerprinting for analytics
• Click statistics
• Bot block monitoring
• Decoy and challenge tracking

*Security notes:*
• Link management commands are disabled for security
• Bot alerts are sent automatically
• Fingerprinting helps detect bots and track devices`;

    return msg;
}

function sendTelegramWelcomeMessage(chatId) {
    if (!ENABLE_TELEGRAM || !telegramBot) return Promise.resolve(false);
    return telegramBot.sendMessage(chatId, formatTelegramHelpMessage(), {
        parseMode: 'Markdown',
        disable_web_page_preview: true,
        reply_markup: getInlineKeyboard().reply_markup
    }).catch(err => {
        logger.error({ error: err.message }, 'Failed to send Telegram welcome message');
        return false;
    });
}

function escapeTelegramMarkdown(text = '') {
    return String(text)
        .replace(/\\/g, '\\\\')
        .replace(/([_.*\[\]()~`>#+\-=|{}.!])/g, '\\$1');
}

function normalizeCampaignId(value) {
    if (value === undefined || value === null || value === '') return '';
    const normalized = String(value).trim();
    return /^[A-Za-z0-9_-]{1,64}$/.test(normalized) ? normalized : '';
}

// ====================== SECURITY HELPERS ======================
function safeEqual(a, b) {
    const ha = crypto.createHash('sha256').update(String(a)).digest();
    const hb = crypto.createHash('sha256').update(String(b)).digest();
    return crypto.timingSafeEqual(ha, hb);
}

function isBotVerdict(verdict) {
    return ['block', 'decoy', 'challenge'].includes(verdict);
}

function formatBotDetectionMessage(code, ip, country, sig, targetUrl) {
    const verdictEmojis = {
        'block': '🚫',
        'challenge': '🔒',
        'decoy': '🎯',
        'slow_down': '🐢',
        'allow': '✅',
        'rate_limit': '⛔'
    };

    const emoji = verdictEmojis[sig.verdict] || '⚠️';
    const safeCode = escapeTelegramMarkdown(code);
    const safeIp = escapeTelegramMarkdown(ip);
    const safeCountry = escapeTelegramMarkdown(country);
    const safeVerdict = escapeTelegramMarkdown(sig.verdict || 'unknown');
    const safeSignals = escapeTelegramMarkdown((sig.signals || []).slice(0, 5).join(', ') || 'None detected');
    const safeTarget = escapeTelegramMarkdown(String(targetUrl || '').substring(0, 60) + (String(targetUrl || '').length > 60 ? '...' : ''));

    return `
${emoji} *Bot Detected!*

📋 *Code:* \`${safeCode}\`
🖥️ *IP:* ${safeIp}
🌍 *Country:* ${safeCountry}
🤖 *Verdict:* ${safeVerdict.toUpperCase()}
📊 *Score:* ${(sig.score * 100).toFixed(1)}%
🔍 *Signals:* ${safeSignals}
🔗 *Target:* ${safeTarget}
⏰ *Time:* ${new Date().toISOString()}
    `;
}

function formatStatsMessage(stats) {
    const uptime = process.uptime();
    const hours = Math.floor(uptime / 3600);
    const minutes = Math.floor((uptime % 3600) / 60);
    
    return `
📊 *Redirect Service Stats*

🔗 *Total Redirects:* ${stats.redirects || 0}
👆 *Total Clicks:* ${stats.total_clicks || 0}
🚫 *Bot Blocks:* ${stats.blocks || 0}
🔒 *Challenges:* ${stats.challenges || 0}
🎯 *Decoys:* ${stats.decoys || 0}

⏱️ *Uptime:* ${hours}h ${minutes}m
📅 *Time:* ${new Date().toISOString()}
    `;
}

// ====================== TELEGRAM COMMAND AUTH ======================
function isTelegramChatAuthorized(chatId) {
    if (!ALLOWED_TELEGRAM_CHAT_IDS.size) return false;
    return ALLOWED_TELEGRAM_CHAT_IDS.has(String(chatId));
}

// ====================== BOUNDED MAP HELPERS ======================
function rememberBotAlert(key) {
    // Store expiry timestamp, not set-time
    botAlertCooldowns.set(key, Date.now() + BOT_ALERT_COOLDOWN_MS);
    // Bound eviction
    if (botAlertCooldowns.size > MAX_BOT_ALERT_KEYS) {
        const toEvict = Math.ceil(MAX_BOT_ALERT_KEYS * 0.1);
        let i = 0;
        for (const k of botAlertCooldowns.keys()) {
            if (i++ >= toEvict) break;
            botAlertCooldowns.delete(k);
        }
    }
}

function rememberUpdateId(id) {
    if (recentUpdateIds.size >= MAX_RECENT_UPDATES) {
        recentUpdateIds.clear();
    }
    recentUpdateIds.add(String(id));
}

// ====================== DEVICE FINGERPRINTING ======================
class DeviceFingerprinter {
    constructor() {
        this.cache = fingerprintCache;
    }

    parseUserAgent(ua) {
        if (!UAParser) {
            return {
                deviceType: 'unknown',
                deviceBrand: 'unknown',
                deviceModel: 'unknown',
                osName: 'unknown',
                osVersion: 'unknown',
                browserName: 'unknown',
                browserVersion: 'unknown',
                engine: 'unknown',
                engineVersion: 'unknown',
                cpu: 'unknown'
            };
        }
        const parser = new UAParser(ua);
        const result = parser.getResult();
        
        return {
            deviceType: result.device.type || 'desktop',
            deviceBrand: result.device.vendor || 'unknown',
            deviceModel: result.device.model || 'unknown',
            osName: result.os.name || 'unknown',
            osVersion: result.os.version || 'unknown',
            browserName: result.browser.name || 'unknown',
            browserVersion: result.browser.version || 'unknown',
            engine: result.engine.name || 'unknown',
            engineVersion: result.engine.version || 'unknown',
            cpu: result.cpu.architecture || 'unknown'
        };
    }

    generateFingerprintId(req, fingerprintData) {
        const components = [
            req.clientIP || 'unknown',
            req.headers['user-agent'] || 'unknown',
            req.headers['accept-language'] || 'unknown',
            fingerprintData.screenResolution || 'unknown',
            fingerprintData.timezone || 'unknown',
            fingerprintData.canvasFingerprint || 'unknown',
            fingerprintData.webglVendor || 'unknown',
            fingerprintData.audioFingerprint || 'unknown',
            FINGERPRINT_SALT
        ];
        
        const combined = components.join('|');
        return crypto.createHash('sha256').update(combined).digest('hex');
    }

    async saveFingerprint(fingerprintId, code, ip, userAgent, fingerprintData, sig) {
        const parsed = this.parseUserAgent(userAgent);
        const isBot = isBotVerdict(sig.verdict);
        const timestamp = new Date().toISOString();

        return new Promise((resolve, reject) => {
            // Use ON CONFLICT for proper upsert
            this.db.run(
                `INSERT INTO device_fingerprints 
                 (fingerprint_id, code, ip, user_agent, device_type, device_brand, device_model,
                  os_name, os_version, browser_name, browser_version, screen_resolution, color_depth,
                  timezone, language, platform, hardware_concurrency, device_memory,
                  webgl_vendor, webgl_renderer, audio_fingerprint, canvas_fingerprint,
                  fonts_fingerprint, is_bot, bot_confidence, first_seen, last_seen, visit_count)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                 ON CONFLICT(fingerprint_id) DO UPDATE SET
                    last_seen = ?,
                    visit_count = visit_count + 1,
                    ip = ?,
                    user_agent = ?,
                    device_type = ?,
                    device_brand = ?,
                    device_model = ?,
                    os_name = ?,
                    os_version = ?,
                    browser_name = ?,
                    browser_version = ?,
                    screen_resolution = ?,
                    color_depth = ?,
                    timezone = ?,
                    language = ?,
                    platform = ?,
                    hardware_concurrency = ?,
                    device_memory = ?,
                    webgl_vendor = ?,
                    webgl_renderer = ?,
                    audio_fingerprint = ?,
                    canvas_fingerprint = ?,
                    fonts_fingerprint = ?,
                    is_bot = ?,
                    bot_confidence = ?`,
                [
                    fingerprintId, code, ip, userAgent,
                    parsed.deviceType, parsed.deviceBrand, parsed.deviceModel,
                    parsed.osName, parsed.osVersion, parsed.browserName, parsed.browserVersion,
                    fingerprintData.screenResolution || 'unknown',
                    fingerprintData.colorDepth || 0,
                    fingerprintData.timezone || 'unknown',
                    fingerprintData.language || 'unknown',
                    fingerprintData.platform || 'unknown',
                    fingerprintData.hardwareConcurrency || 0,
                    fingerprintData.deviceMemory || 0,
                    fingerprintData.webglVendor || 'unknown',
                    fingerprintData.webglRenderer || 'unknown',
                    fingerprintData.audioFingerprint || 'unknown',
                    fingerprintData.canvasFingerprint || 'unknown',
                    fingerprintData.fontsFingerprint || 'unknown',
                    isBot ? 1 : 0,
                    sig.confidence || 0,
                    timestamp,
                    // ON UPDATE values:
                    timestamp,
                    ip,
                    userAgent,
                    parsed.deviceType, parsed.deviceBrand, parsed.deviceModel,
                    parsed.osName, parsed.osVersion, parsed.browserName, parsed.browserVersion,
                    fingerprintData.screenResolution || 'unknown',
                    fingerprintData.colorDepth || 0,
                    fingerprintData.timezone || 'unknown',
                    fingerprintData.language || 'unknown',
                    fingerprintData.platform || 'unknown',
                    fingerprintData.hardwareConcurrency || 0,
                    fingerprintData.deviceMemory || 0,
                    fingerprintData.webglVendor || 'unknown',
                    fingerprintData.webglRenderer || 'unknown',
                    fingerprintData.audioFingerprint || 'unknown',
                    fingerprintData.canvasFingerprint || 'unknown',
                    fingerprintData.fontsFingerprint || 'unknown',
                    isBot ? 1 : 0,
                    sig.confidence || 0
                ],
                (err) => {
                    if (err) reject(err);
                    else resolve();
                }
            );
        });
    }

    async logClickEvent(code, fingerprintId, ip, country, userAgent, referrer, sig) {
        const parsed = this.parseUserAgent(userAgent);
        
        return new Promise((resolve, reject) => {
            this.db.run(
                `INSERT INTO click_events 
                 (code, fingerprint_id, ip, country, user_agent, referrer, timestamp,
                  bot_score, bot_verdict, device_type, os_name, browser_name)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [
                    code, fingerprintId, ip, country, userAgent, referrer || '',
                    new Date().toISOString(),
                    sig.score || 0,
                    sig.verdict || 'allow',
                    parsed.deviceType,
                    parsed.osName,
                    parsed.browserName
                ],
                (err) => {
                    if (err) reject(err);
                    else resolve();
                }
            );
        });
    }

    async getFingerprintStats(fingerprintId) {
        return new Promise((resolve, reject) => {
            this.db.get(
                `SELECT * FROM device_fingerprints WHERE fingerprint_id = ?`,
                [fingerprintId],
                (err, row) => {
                    if (err) reject(err);
                    else resolve(row);
                }
            );
        });
    }

    async getDeviceStats(code = null) {
        const whereClause = code ? 'WHERE code = ?' : '';
        const params = code ? [code] : [];
        const cutoff = new Date(Date.now() - 7 * 24 * 3600 * 1000).toISOString();
        
        return new Promise((resolve, reject) => {
            const queries = {
                devices: `SELECT device_type, COUNT(*) as count FROM device_fingerprints ${whereClause ? whereClause + ' AND' : 'WHERE'} last_seen >= ? GROUP BY device_type`,
                browsers: `SELECT browser_name, COUNT(*) as count FROM device_fingerprints ${whereClause ? whereClause + ' AND' : 'WHERE'} last_seen >= ? GROUP BY browser_name`,
                os: `SELECT os_name, COUNT(*) as count FROM device_fingerprints ${whereClause ? whereClause + ' AND' : 'WHERE'} last_seen >= ? GROUP BY os_name`,
                bots: `SELECT is_bot, COUNT(*) as count FROM device_fingerprints ${whereClause ? whereClause + ' AND' : 'WHERE'} last_seen >= ? GROUP BY is_bot`,
                recent: `SELECT device_type, browser_name, os_name, last_seen FROM device_fingerprints ${whereClause ? whereClause + ' AND' : 'WHERE'} last_seen >= ? ORDER BY last_seen DESC LIMIT 10`
            };
            
            const results = {};
            let completed = 0;
            const total = Object.keys(queries).length;
            
            for (const [key, query] of Object.entries(queries)) {
                const queryParams = [...params, cutoff];
                this.db.all(query, queryParams, (err, rows) => {
                    if (err) reject(err);
                    else {
                        results[key] = rows || [];
                        completed++;
                        if (completed === total) {
                            resolve(results);
                        }
                    }
                });
            }
        });
    }

    async getClickEvents(code = null, limit = 100) {
        const clampedLimit = Math.min(Math.max(parseInt(limit, 10) || 100, 1), 1000);
        const whereClause = code ? 'WHERE code = ?' : '';
        const params = code ? [code, clampedLimit] : [clampedLimit];
        
        return new Promise((resolve, reject) => {
            this.db.all(
                `SELECT * FROM click_events ${whereClause} ORDER BY timestamp DESC LIMIT ?`,
                params,
                (err, rows) => {
                    if (err) reject(err);
                    else resolve(rows || []);
                }
            );
        });
    }

    checkRateLimit(ip) {
        const now = Date.now();
        const key = String(ip || 'unknown');
        const entry = fingerprintRateLimit.get(key);

        if (!entry || now - entry.windowStart > 60000) {
            fingerprintRateLimit.set(key, { count: 1, windowStart: now });
            return true;
        }

        if (entry.count >= FINGERPRINT_RATE_LIMIT) {
            return false;
        }

        entry.count++;
        return true;
    }

    // Helper to get db instance
    get db() {
        return dbInstance.db;
    }
}

// Set db reference after initialization
let dbInstance = null;

// ====================== IP VALIDATION ======================
function expandV6ToBytes(ip) {
    const s = String(ip).toLowerCase();
    if (!/^[0-9a-f:]+$/.test(s) || s.includes(':::')) return null;
    const [head, tail] = s.split('::');
    const headParts = head ? head.split(':').filter(Boolean) : [];
    const tailParts = tail ? tail.split(':').filter(Boolean) : [];
    const missing = 8 - headParts.length - tailParts.length;
    if (missing < 0) return null;
    const parts = [...headParts, ...Array(missing).fill('0'), ...tailParts];
    if (parts.length !== 8 || parts.some(p => !/^[0-9a-f]{1,4}$/.test(p))) return null;
    const bytes = [];
    for (const p of parts) {
        const v = parseInt(p, 16);
        bytes.push((v >> 8) & 0xff, v & 0xff);
    }
    return bytes;
}

function v6InPrefix(ip, cidr) {
    const bytes = expandV6ToBytes(ip);
    if (!bytes) return false;
    const [net, bitsStr] = cidr.split('/');
    const bits = parseInt(bitsStr, 10);
    if (!Number.isInteger(bits) || bits < 0 || bits > 128) return false;
    const netBytes = expandV6ToBytes(net);
    if (!netBytes) return false;
    const full = bits >> 3, rem = bits & 7;
    for (let i = 0; i < full; i++) {
        if (bytes[i] !== netBytes[i]) return false;
    }
    if (rem) {
        const mask = 0xff << (8 - rem);
        if ((bytes[full] & mask) !== (netBytes[full] & mask)) return false;
    }
    return true;
}

function isIpInCidrV6(ip, cidr) {
    return v6InPrefix(ip, cidr);
}

const RESERVED_V6_PREFIXES = [
    '::/128', '::1/128', '::ffff:0:0/96', '64:ff9b::/96', '64:ff9b:1::/48',
    '100::/64', '2001:db8::/32', '2001:2::/48', '2001:10::/28', '2001:20::/28',
    '2002::/16', 'fc00::/7', 'fe80::/10', 'ff00::/8',
];

function isReservedIpv4(ip) {
    const parts = String(ip).split('.').map(Number);
    if (parts.length !== 4 || parts.some(p => !Number.isInteger(p) || p < 0 || p > 255)) return true;
    const [a, b, c] = parts;
    return (
        a === 0 || a === 10 || a === 127 || a >= 224 || a === 255 ||
        (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
        (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) ||
        (a === 192 && b === 0 && c === 0) || (a === 192 && b === 0 && c === 2) ||
        (a === 198 && b === 51 && c === 100) || (a === 203 && b === 0 && c === 113) ||
        (a === 198 && (b === 18 || b === 19)) || (a === 192 && b === 88 && c === 99)
    );
}

function isReservedIpv6(ip) {
    return RESERVED_V6_PREFIXES.some(p => v6InPrefix(ip, p));
}

function isReservedIp(input) {
    let ip = String(input || '').trim().toLowerCase();
    if (!ip) return false;
    if (ip.startsWith('[') && ip.endsWith(']')) ip = ip.slice(1, -1);

    const family = net.isIP(ip);
    if (family === 6) {
        const embedded = ip.match(/^(.*:)(\d{1,3}(?:\.\d{1,3}){3})$/);
        if (embedded) {
            const p = embedded[2].split('.').map(Number);
            if (p.length === 4 && p.every(x => x >= 0 && x <= 255)) {
                return isReservedIpv4(embedded[2]);
            }
            return true;
        }
        const hexMapped = ip.match(/^(.*::ffff:)([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
        if (hexMapped) {
            const a = parseInt(hexMapped[2], 16), b = parseInt(hexMapped[3], 16);
            return isReservedIpv4(`${(a >> 8) & 0xff}.${a & 0xff}.${(b >> 8) & 0xff}.${b & 0xff}`);
        }
        return isReservedIpv6(ip);
    }
    if (family === 4) return isReservedIpv4(ip);

    const numMatch = ip.match(/^(0x[0-9a-f]+|\d+)$/);
    if (numMatch) {
        const n = numMatch[1].startsWith('0x') ? parseInt(numMatch[1], 16) : Number(numMatch[1]);
        if (Number.isInteger(n) && n >= 0 && n <= 0xffffffff) {
            return isReservedIpv4(`${(n >>> 24) & 0xff}.${(n >>> 16) & 0xff}.${(n >>> 8) & 0xff}.${n & 0xff}`);
        }
        return true;
    }
    return false;
}

// ====================== DNS LOOKUP ======================
let activeDnsLookups = 0;

function lookupWithTimeout(hostname) {
    return new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('dns_lookup_timeout')), DNS_LOOKUP_TIMEOUT_MS);
        dns.lookup(hostname, { all: true, verbatim: true }, (err, addrs) => {
            clearTimeout(timer);
            if (err) reject(err);
            else resolve(addrs);
        });
    });
}

async function lookupHost(hostname) {
    const cached = dnsCache.get(hostname);
    if (cached !== undefined) return cached;

    const start = Date.now();
    let waited = false;
    while (activeDnsLookups >= MAX_CONCURRENT_DNS_LOOKUPS) {
        if (!waited) {
            logger.debug({ hostname, active: activeDnsLookups }, 'dns_semaphore_wait');
            waited = true;
        }
        if (Date.now() - start >= DNS_SEMAPHORE_TIMEOUT_MS) return null;
        await new Promise(r => setTimeout(r, 10));
    }
    activeDnsLookups++;
    try {
        const addrs = await lookupWithTimeout(hostname);
        dnsCache.set(hostname, addrs);
        return addrs;
    } catch (e) {
        dnsCache.set(hostname, null);
        return null;
    } finally {
        activeDnsLookups--;
    }
}

async function isAllowedTarget(rawUrl) {
    let parsed;
    try {
        parsed = new URL(String(rawUrl || '').trim());
    } catch {
        return false;
    }
    if (parsed.protocol !== 'https:') return false;
    if (parsed.username || parsed.password) return false;
    if (!parsed.hostname) return false;

    const host = parsed.hostname.replace(/^\[|\]$/g, '').replace(/\.$/, '').toLowerCase();
    if (net.isIP(host)) return !isReservedIp(host);
    if (/^(0x[0-9a-f]+|\d+)$/i.test(host)) return false;

    const addrs = await lookupHost(host);
    if (!addrs || addrs.length === 0) return false;
    return addrs.every(a => !isReservedIp(a.address));
}

// ====================== BEHAVIORAL ANALYZER ======================
class BehavioralAnalyzer {
    constructor() {
        this.rateLimits = rateLimitStore;
        this.maxRateLimitEntries = MAX_RATE_LIMIT_ENTRIES;
        setInterval(() => this.evictRateLimitEntries(Date.now()), 60000);
    }

    getRateLimitKey(ip, ua) {
        const normalizedIp = String(ip || 'unknown');
        const normalizedUa = String(ua || '').trim().slice(0, 256);
        return crypto.createHash('sha256').update(`${normalizedIp}|${normalizedUa}`).digest('hex');
    }

    evictRateLimitEntries(now) {
        const staleThreshold = 60000;
        for (const [key, entry] of Array.from(this.rateLimits.entries())) {
            if (now - entry.windowStart > staleThreshold) {
                this.rateLimits.delete(key);
            }
        }

        if (this.rateLimits.size > this.maxRateLimitEntries) {
            const toDelete = this.rateLimits.size - this.maxRateLimitEntries;
            const keys = Array.from(this.rateLimits.keys()).slice(0, toDelete);
            for (const key of keys) {
                this.rateLimits.delete(key);
            }
        }
    }

    analyze(headers, ip) {
        const sig = {
            score: 0.0,
            confidence: 0.0,
            verdict: 'allow',
            signals: [],
            environmental: {}
        };

        const scores = [];
        const ua = headers['user-agent'] || '';

        const uaResult = this.analyzeUserAgent(ua);
        if (uaResult) {
            scores.push(uaResult);
            sig.signals.push(...uaResult.signals);
        }

        const envResult = this.analyzeEnvironment(ip, headers);
        if (envResult.signals.length > 0) {
            sig.signals.push(...envResult.signals);
            sig.environmental = envResult;
            scores.push({
                category: 'environment',
                score: envResult.score || 0,
                weight: 1.5,
                signals: envResult.signals
            });
        }

        const headerResult = this.analyzeHeaders(headers);
        if (headerResult) {
            scores.push(headerResult);
            sig.signals.push(...headerResult.signals);
        }

        const rateInfo = this.checkRateLimit(ip, ua);
        if (rateInfo.isLimited) {
            sig.verdict = 'rate_limit';
            sig.score = 0.85;
            sig.confidence = 0.9;
            sig.signals.push('rate_limited');
            sig.environmental.rateLimit = rateInfo;
            return sig;
        }

        if (scores.length > 0) {
            const combined = this.combineScores(scores);
            sig.score = combined.score;
            sig.confidence = combined.confidence;
            sig.verdict = this.decideVerdict(sig);
        }

        return sig;
    }

    analyzeUserAgent(ua) {
        if (!ua) {
            return {
                category: 'missing',
                score: 0.5,
                weight: 1.0,
                signals: ['missing_user_agent']
            };
        }

        const uaLower = ua.toLowerCase();
        
        for (const [category, pattern] of Object.entries(BOT_PATTERNS)) {
            if (pattern.test(uaLower)) {
                const scores = {
                    headless: 0.9,
                    crawler: 0.4,
                    ai_crawler: 0.85,
                    security_scanner: 0.95,
                    http_library: 0.7,
                    email_scanner: 0.1
                };
                const weights = {
                    headless: 2.0,
                    crawler: 1.0,
                    ai_crawler: 2.5,
                    security_scanner: 3.0,
                    http_library: 1.5,
                    email_scanner: 0.5
                };
                return {
                    category: category,
                    score: scores[category] || 0.5,
                    weight: weights[category] || 1.0,
                    signals: [`${category}_detected`]
                };
            }
        }

        if (!/Mozilla|Chrome|Safari|Firefox|Edge/.test(ua)) {
            return {
                category: 'non_standard',
                score: 0.3,
                weight: 0.8,
                signals: ['non_standard_ua']
            };
        }

        return null;
    }

    analyzeEnvironment(ip, headers) {
        const result = { score: 0.0, signals: [], isDatacenter: false };

        const allPrefixes = { ...DATACENTER_PREFIXES, ...DATACENTER_IPV4_MAPPED };
        for (const [prefix, provider] of Object.entries(allPrefixes)) {
            if (ip.startsWith(prefix)) {
                result.isDatacenter = true;
                result.score += 0.3;
                result.signals.push(`datacenter:${provider}`);
                break;
            }
        }

        if (!headers['accept-language']) {
            result.score += 0.15;
            result.signals.push('missing_accept_language');
        }

        if (!headers['accept']) {
            result.score += 0.1;
            result.signals.push('missing_accept');
        }

        result.score = Math.min(1.0, result.score);
        return result;
    }

    analyzeHeaders(headers) {
        let score = 0.0;
        const signals = [];

        const secFetchHeaders = ['sec-fetch-site', 'sec-fetch-mode', 'sec-fetch-dest'];
        const present = secFetchHeaders.filter(h => headers[h]).length;
        
        if (present === 0) {
            score += 0.35;
            signals.push('missing_sec_fetch');
        } else if (present < 2) {
            score += 0.15;
            signals.push('partial_sec_fetch');
        }

        if (signals.length === 0) return null;

        return {
            category: 'headers',
            score: Math.min(1.0, score),
            weight: 1.0,
            signals: signals
        };
    }

    checkRateLimit(ip, ua) {
        const now = Date.now();
        const isBot = /bot|crawler|scanner/i.test(ua);
        const key = this.getRateLimitKey(ip, ua);

        if (!this.rateLimits.has(key)) {
            this.rateLimits.set(key, { count: 0, windowStart: now });
        }

        const entry = this.rateLimits.get(key);

        if (now - entry.windowStart > 60000) {
            entry.count = 0;
            entry.windowStart = now;
        }

        const limit = isBot ? 10 : 60;
        entry.count++;

        return {
            isLimited: entry.count > limit,
            count: entry.count,
            limit: limit,
            remaining: Math.max(0, limit - entry.count),
            resetAt: entry.windowStart + 60000
        };
    }

    combineScores(scores) {
        let totalWeight = 0;
        let weightedSum = 0;

        for (const s of scores) {
            const w = s.weight || 1.0;
            weightedSum += s.score * w;
            totalWeight += w;
        }

        const score = totalWeight > 0 ? weightedSum / totalWeight : 0;
        return {
            score: Math.min(1.0, score),
            confidence: Math.min(1.0, score)
        };
    }

    decideVerdict(sig) {
        const score = sig.score;

        if (score > 0.85) return 'block';
        if (score > 0.75) {
            const signalsStr = JSON.stringify(sig.signals);
            if (signalsStr.includes('ai_crawler')) return 'decoy';
            if (signalsStr.includes('headless')) return 'challenge';
            return 'slow_down';
        }
        if (score > 0.5) return 'challenge';
        if (score > 0.3) return 'slow_down';
        return 'allow';
    }
}

// ====================== CHALLENGE ENGINE ======================
function toJsString(value) {
    return JSON.stringify(String(value)).replace(/</g, '\\u003C');
}

function escapeHtmlAttribute(value) {
    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/"/g, '&quot;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
}

class ChallengeEngine {
    constructor() {
        this.challenges = new Map();
        this.decoyUrls = BOT_URLS;
        this.verifyRateLimit = new Map();
        setInterval(() => this.cleanup(), 60000);
    }

    cleanup() {
        const now = Date.now();
        if (this.challenges.size > MAX_CHALLENGES) {
            const toDelete = this.challenges.size - MAX_CHALLENGES;
            const keys = Array.from(this.challenges.keys()).slice(0, toDelete);
            for (const key of keys) {
                this.challenges.delete(key);
            }
        }
        
        for (const [id, data] of this.challenges) {
            if (now > data.expiresAt) {
                this.challenges.delete(id);
            }
        }
        
        for (const [ip, entry] of this.verifyRateLimit) {
            if (now > entry.windowStart + 60000) {
                this.verifyRateLimit.delete(ip);
            }
        }
    }

    checkVerifyRateLimit(ip) {
        const now = Date.now();
        const key = String(ip || 'unknown');
        const existing = this.verifyRateLimit.get(key);

        if (!existing || now - existing.windowStart > 60000) {
            this.verifyRateLimit.set(key, { windowStart: now, count: 1 });
            return true;
        }

        if (existing.count >= 10) {
            return false;
        }

        existing.count += 1;
        return true;
    }

    createChallenge(targetUrl, botScore = 0, nonce = '') {
        let powBits = 12;
        let timeout = 8;

        if (botScore > 0.75) {
            powBits = 16;
            timeout = 15;
        } else if (botScore > 0.5) {
            powBits = 14;
            timeout = 10;
        }

        const challengeId = crypto.randomBytes(16).toString('hex');
        const powPrefix = '0'.repeat(powBits);
        const startTime = Date.now();

        this.challenges.set(challengeId, {
            createdAt: startTime,
            startTime: startTime,
            expiresAt: startTime + 120000,
            targetUrl: targetUrl,
            powPrefix: powPrefix,
            timeout: timeout,
            verified: false
        });

        const html = this.generateChallengePage(challengeId, targetUrl, powPrefix, timeout, startTime, nonce);
        return { challengeId, html };
    }

    generateChallengePage(challengeId, targetUrl, powPrefix, timeout, startTime, nonce = '') {
        const safeTarget = toJsString(targetUrl);
        const safeChallengeId = toJsString(challengeId);
        const safePowPrefix = toJsString(powPrefix);
        const safeDecoyUrls = `[${this.decoyUrls.map(url => toJsString(url)).join(', ')}]`;
        const safeNonce = escapeHtmlAttribute(nonce);
        
        const fingerprintScript = ENABLE_FINGERPRINTING ? `
        // ====== FINGERPRINT COLLECTION ======
        async function collectFingerprint() {
            const fp = {};
            
            fp.screenResolution = \`\${window.screen.width}x\${window.screen.height}\`;
            fp.colorDepth = window.screen.colorDepth;
            fp.pixelRatio = window.devicePixelRatio || 0;
            fp.timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
            fp.timezoneOffset = new Date().getTimezoneOffset();
            fp.language = navigator.language;
            fp.languages = navigator.languages || [];
            fp.platform = navigator.platform;
            fp.hardwareConcurrency = navigator.hardwareConcurrency || 0;
            fp.deviceMemory = navigator.deviceMemory || 0;
            
            try {
                const canvas = document.createElement('canvas');
                const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
                if (gl) {
                    fp.webglVendor = gl.getParameter(gl.VENDOR) || 'unknown';
                    fp.webglRenderer = gl.getParameter(gl.RENDERER) || 'unknown';
                    const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
                    if (debugInfo) {
                        fp.webglVendor = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) || fp.webglVendor;
                        fp.webglRenderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) || fp.webglRenderer;
                    }
                }
            } catch(e) { fp.webglVendor = 'error'; fp.webglRenderer = 'error'; }
            
            try {
                const canvas = document.createElement('canvas');
                canvas.width = 256;
                canvas.height = 64;
                const ctx = canvas.getContext('2d');
                ctx.textBaseline = 'top';
                ctx.font = '14px Arial';
                ctx.fillStyle = '#f60';
                ctx.fillRect(0, 0, 16, 16);
                ctx.fillStyle = '#069';
                ctx.fillText('Fingerprint', 2, 0);
                ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
                ctx.fillText('Canvas Fingerprint', 4, 17);
                ctx.beginPath();
                ctx.arc(50, 50, 20, 0, Math.PI * 2, true);
                ctx.stroke();
                fp.canvasFingerprint = canvas.toDataURL().substring(0, 200);
            } catch(e) { fp.canvasFingerprint = 'error'; }
            
            try {
                let audioCtx;
                try {
                    audioCtx = new (window.AudioContext || window.webkitAudioContext)();
                } catch(e) { /* AudioContext not supported */ }
                
                if (audioCtx) {
                    if (audioCtx.state === 'running') {
                        const oscillator = audioCtx.createOscillator();
                        const analyser = audioCtx.createAnalyser();
                        oscillator.connect(analyser);
                        analyser.fftSize = 2048;
                        oscillator.start();
                        const bufferLength = analyser.frequencyBinCount;
                        const dataArray = new Uint8Array(bufferLength);
                        analyser.getByteFrequencyData(dataArray);
                        fp.audioFingerprint = Array.from(dataArray.slice(0, 50)).join(',');
                        oscillator.disconnect();
                    } else if (audioCtx.state === 'suspended') {
                        try {
                            await audioCtx.resume();
                            const oscillator = audioCtx.createOscillator();
                            const analyser = audioCtx.createAnalyser();
                            oscillator.connect(analyser);
                            analyser.fftSize = 2048;
                            oscillator.start();
                            const bufferLength = analyser.frequencyBinCount;
                            const dataArray = new Uint8Array(bufferLength);
                            analyser.getByteFrequencyData(dataArray);
                            fp.audioFingerprint = Array.from(dataArray.slice(0, 50)).join(',');
                            oscillator.disconnect();
                        } catch(e) { /* Could not resume */ }
                    }
                }
            } catch(e) { fp.audioFingerprint = 'error'; }
            
            fp.fontsFingerprint = '';
            const fontList = ['Arial', 'Helvetica', 'Times New Roman', 'Courier New', 'Georgia', 'Verdana'];
            const testDiv = document.createElement('div');
            testDiv.style.visibility = 'hidden';
            testDiv.style.position = 'absolute';
            testDiv.style.top = '-9999px';
            document.body.appendChild(testDiv);
            const baseFont = 'monospace';
            testDiv.textContent = 'mmmmmmmmmmlli';
            testDiv.style.fontFamily = baseFont;
            const baseWidth = testDiv.offsetWidth;
            for (const font of fontList) {
                testDiv.style.fontFamily = \`"\${font}", \${baseFont}\`;
                if (testDiv.offsetWidth !== baseWidth) {
                    fp.fontsFingerprint += font + ',';
                }
            }
            document.body.removeChild(testDiv);
            
            fp.plugins = Array.from(navigator.plugins).map(p => p.name).join(',');
            fp.touchSupport = ('ontouchstart' in window) || (navigator.maxTouchPoints > 0);
            
            if (!window.isSecureContext) {
                fp.insecure = true;
            }
            
            return fp;
        }
        
        const token = document.querySelector('[data-token]')?.dataset?.token || '';
        if (token) {
            collectFingerprint().then(fp => {
                const data = JSON.stringify({ token, fingerprint: fp });
                if (navigator.sendBeacon) {
                    navigator.sendBeacon('/api/fingerprint', data);
                } else {
                    fetch('/api/fingerprint', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: data,
                        keepalive: true
                    }).catch(e => console.warn('Fingerprint collection failed', e));
                }
            }).catch(e => console.warn('Fingerprint collection failed', e));
        }
        ` : '';

        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verifying connection</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            background: #ffffff;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            font-weight: 400;
            line-height: 1.5;
            color: #1e1e1e;
            margin: 0;
            padding: 1.5rem;
        }
        .card {
            max-width: 480px;
            width: 100%;
            background: #ffffff;
            padding: 2.5rem 1.5rem;
            text-align: center;
        }
        .verifying-title {
            font-size: 1.5rem;
            font-weight: 450;
            letter-spacing: -0.02em;
            color: #1a1a1a;
            margin-bottom: 1.5rem;
            display: inline-block;
        }
        .dot-loader {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.5rem;
            margin: 1.25rem 0 1.5rem 0;
            height: 2.5rem;
        }
        .dot {
            width: 0.6rem;
            height: 0.6rem;
            background: #1a1a1a;
            border-radius: 50%;
            display: inline-block;
            opacity: 0.2;
            animation: dotPulse 1.4s infinite ease-in-out both;
        }
        .dot:nth-child(1) { animation-delay: -0.32s; }
        .dot:nth-child(2) { animation-delay: -0.16s; }
        .dot:nth-child(3) { animation-delay: 0s; }
        @keyframes dotPulse {
            0%, 80%, 100% { opacity: 0.2; transform: scale(0.9); }
            40% { opacity: 1; transform: scale(1.1); }
        }
        .progress-track {
            width: 100%;
            height: 2px;
            background: #eaeaea;
            margin: 1.5rem 0 1rem 0;
            overflow: hidden;
        }
        .progress-fill {
            height: 100%;
            width: 0%;
            background: #1a1a1a;
            transition: width 0.25s ease;
        }
        .status-text {
            font-size: 0.85rem;
            color: #6b6b6b;
            letter-spacing: 0.01em;
            margin-top: 0.25rem;
            font-weight: 350;
            min-height: 1.6rem;
        }
        .honeypot {
            position: absolute;
            left: -9999px;
            top: -9999px;
            opacity: 0;
            height: 0;
            overflow: hidden;
            pointer-events: none;
        }
        .divider {
            width: 2.5rem;
            height: 1px;
            background: #d0d0d0;
            margin: 1.25rem auto 0.75rem auto;
        }
        .card, body, .dot-loader, .verifying-title { background: #ffffff; }
        @media (prefers-reduced-motion: reduce) {
            .dot { animation: none; opacity: 0.5; }
            .dot:nth-child(1), .dot:nth-child(2), .dot:nth-child(3) { animation: none; }
        }
    </style>
</head>
<body>
    <div class="card" data-token="${escapeHtmlAttribute(challengeId)}">
        <div class="verifying-title">verifying connection</div>
        <div class="dot-loader" aria-label="loading">
            <span class="dot"></span><span class="dot"></span><span class="dot"></span>
        </div>
        <div class="progress-track" role="progressbar" aria-valuenow="0" aria-valuemin="0" aria-valuemax="100">
            <div class="progress-fill" id="progressFill" style="width: 0%;"></div>
        </div>
        <div class="status-text" id="statusMessage">checking browser integrity</div>
        <div class="divider"></div>
        <div class="honeypot">
            <input type="text" id="hp_name" name="hp_name" value="">
        </div>
    </div>
    <script nonce="${safeNonce}">
        ${fingerprintScript}
        (function() {
            'use strict';
            const TARGET = ${safeTarget};
            const CHALLENGE_ID = ${safeChallengeId};
            const POW_PREFIX = ${safePowPrefix};
            const START = ${startTime};
            const TIMEOUT = ${timeout * 1000};
            const DECOY_URLS = ${safeDecoyUrls};
            const statusEl = document.getElementById('statusMessage');
            const progressFill = document.getElementById('progressFill');
            const hpInput = document.getElementById('hp_name');
            let nonce = 0;
            let solved = false;

            function goDecoy(reason) {
                if (solved) return;
                solved = true;
                statusEl.textContent = 'redirecting...';
                sessionStorage.setItem('_apex_reason', reason);
                const idx = Math.floor(Math.random() * DECOY_URLS.length);
                window.location.href = DECOY_URLS[idx];
            }

            if (!window.isSecureContext) {
                goDecoy('insecure_context');
                return;
            }

            function goSlow() {
                if (solved) return;
                const delay = 3000 + Math.random() * 4000;
                statusEl.textContent = 'additional verification required...';
                setTimeout(() => {
                    if (!solved) startPow();
                }, delay);
            }

            async function startPow() {
                if (solved) return;
                const encoder = new TextEncoder();
                const data = CHALLENGE_ID + ':' + START;
                const maxIter = 500000;
                const startTime = Date.now();
                const timeLimit = Math.min(TIMEOUT * 0.8, 5000);
                nonce = 0;

                while (nonce < maxIter) {
                    const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(data + nonce));
                    const hashArray = Array.from(new Uint8Array(hashBuffer));
                    const hex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
                    if (hex.startsWith(POW_PREFIX)) {
                        progressFill.style.width = '100%';
                        statusEl.textContent = 'verified · redirecting';
                        try {
                            const resp = await fetch('/verify-challenge', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({
                                    challenge_id: CHALLENGE_ID,
                                    nonce: nonce,
                                    duration: Date.now() - START
                                })
                            });
                            const data = await resp.json();
                            if (data.verified) {
                                await new Promise(r => setTimeout(r, 200));
                                window.location.href = TARGET;
                            } else {
                                goDecoy('verify_failed');
                            }
                        } catch (e) {
                            goDecoy('verify_error');
                        }
                        solved = true;
                        return;
                    }
                    nonce++;
                    if (nonce % 500 === 0) {
                        const elapsed = Date.now() - startTime;
                        const pct = Math.min(90, (elapsed / timeLimit) * 90);
                        progressFill.style.width = pct + '%';
                        statusEl.textContent = \`verifying · \${Math.floor(elapsed / 100)}s\`;
                        if (elapsed > timeLimit) break;
                        await new Promise(r => setTimeout(r, 0));
                    }
                }
                if (!solved) goDecoy('pow_timeout');
            }

            function runInitialChecks() {
                if (hpInput && hpInput.value) { goDecoy('honeypot'); return; }
                if (navigator.webdriver) { goDecoy('webdriver'); return; }
                if (navigator.plugins.length === 0) { goSlow(); return; }
                if (window.screen.width === 0 || window.screen.height === 0) { goDecoy('zero_screen'); return; }
                let hasWebGL = false;
                try {
                    const canvas = document.createElement('canvas');
                    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
                    hasWebGL = !!gl;
                } catch (e) { goSlow(); return; }
                if (!hasWebGL) { goSlow(); return; }
                statusEl.textContent = 'running security checks...';
                progressFill.style.width = '10%';
                setTimeout(() => {
                    if (!solved) {
                        const extraDelay = 300 + Math.random() * 500;
                        setTimeout(() => { if (!solved) startPow(); }, extraDelay);
                    }
                }, 200 + Math.random() * 400);
            }

            runInitialChecks();
            setTimeout(() => {
                if (!solved) {
                    statusEl.textContent = 'verification timed out';
                    goDecoy('global_timeout');
                }
            }, TIMEOUT + 2000);
        })();
    </script>
</body>
</html>`;
    }

    verify(challengeId, nonce, duration, ip, userAgent) {
        const challenge = this.challenges.get(challengeId);
        if (!challenge) return false;
        if (challenge.verified) {
            this.challenges.delete(challengeId);
            return false;
        }
        if (Date.now() > challenge.expiresAt) {
            this.challenges.delete(challengeId);
            return false;
        }

        const safeNonce = Number(nonce);
        const clientDuration = duration !== undefined ? Number(duration) : null;
        const serverElapsed = Date.now() - challenge.startTime;
        
        if (!Number.isInteger(safeNonce) || safeNonce < 0) return false;
        // Stricter timing validation using server-side time
        if (serverElapsed < 50 || serverElapsed > 120000) return false;
        if (!this.checkVerifyRateLimit(ip)) return false;

        const hash = crypto.createHash('sha256')
            .update(`${challengeId}:${challenge.startTime}${safeNonce}`)
            .digest('hex');

        if (!hash.startsWith(challenge.powPrefix)) {
            return false;
        }

        challenge.verified = true;
        challenge.verifiedAt = Date.now();
        challenge.ip = ip;
        // Store client duration if provided (log-only)
        if (clientDuration !== null) {
            challenge.clientDuration = clientDuration;
        }
        challenge.nonce = safeNonce;
        challenge.serverElapsed = serverElapsed;
        
        solvedSessions.set(challengeId, {
            ip: ip,
            ua: userAgent || '',
            solvedAt: Date.now()
        });
        
        this.challenges.delete(challengeId);
        return true;
    }
}

// ====================== HELPERS ======================
function generateShortCode(length = 6) {
    const chars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    let code = '';
    while (code.length < length) {
        const bytes = crypto.randomBytes(length);
        for (const b of bytes) {
            if (code.length >= length) break;
            if (b < 256 - (256 % 62)) {
                code += chars[b % chars.length];
            }
        }
    }
    return code;
}

function parseCookies(cookieHeader = '') {
    return cookieHeader.split(';').reduce((cookies, pair) => {
        const [name, ...rest] = pair.trim().split('=');
        if (!name) return cookies;
        try {
            cookies[name] = decodeURIComponent(rest.join('='));
        } catch (e) {
            cookies[name] = rest.join('=');
        }
        return cookies;
    }, {});
}

function signSessionValue(sessionId, req) {
    const ip = getClientIP(req);
    const ua = req.headers['user-agent'] || '';
    return crypto.createHmac('sha256', SESSION_SECRET)
        .update(`${sessionId}:${ip}:${ua}`)
        .digest('hex');
}

function issueSignedSession(req, res) {
    const sessionId = crypto.randomBytes(16).toString('hex');
    const signature = signSessionValue(sessionId, req);
    res.cookie(SESSION_COOKIE_NAME, `${sessionId}.${signature}`, {
        httpOnly: true,
        sameSite: 'lax',
        secure: BASE_URL.startsWith('https://'),
        maxAge: SESSION_TTL_MS
    });
    return `${sessionId}.${signature}`;
}

function verifySignedSession(req) {
    const cookies = parseCookies(req.headers.cookie || '');
    const cookieValue = cookies[SESSION_COOKIE_NAME];
    if (!cookieValue || typeof cookieValue !== 'string') return null;

    const [sessionId, signature] = String(cookieValue).split('.');
    if (!sessionId || !signature) return null;

    const expected = signSessionValue(sessionId, req);
    const actual = Buffer.from(signature, 'hex');
    const expectedBuf = Buffer.from(expected, 'hex');
    if (actual.length !== expectedBuf.length) return null;

    if (!crypto.timingSafeEqual(actual, expectedBuf)) return null;
    
    let solved = false;
    const now = Date.now();
    for (const [id, data] of solvedSessions) {
        if (data.ip === getClientIP(req) && data.ua === (req.headers['user-agent'] || '')) {
            if (now - data.solvedAt <= SOLVED_SESSION_TTL) {
                solved = true;
                break;
            }
        }
    }
    
    return { sessionId, solved };
}

function getCleanShortUrl(code) {
    const base = (BASE_URL || 'http://localhost:10000').replace(/\/$/, '');
    return `${base}/${code}`;
}

function validateHostHeader(req) {
    const hostHeader = req.get('host');
    if (!hostHeader) return true;
    
    const expectedHost = (() => {
        try {
            return new URL(BASE_URL).hostname.toLowerCase();
        } catch (e) {
            return 'localhost';
        }
    })();
    const expectedPort = (() => {
        try {
            return new URL(BASE_URL).port || (BASE_URL.startsWith('https') ? '443' : '80');
        } catch (e) {
            return String(PORT);
        }
    })();
    
    let hostname = hostHeader;
    let port = '';
    if (hostHeader.includes(':')) {
        if (hostHeader.startsWith('[')) {
            const endBracket = hostHeader.indexOf(']');
            if (endBracket !== -1) {
                hostname = hostHeader.substring(1, endBracket).toLowerCase();
                port = hostHeader.substring(endBracket + 2) || '';
            }
        } else {
            const parts = hostHeader.split(':');
            hostname = parts[0].toLowerCase();
            port = parts.slice(1).join(':');
        }
    }
    
    if (hostname !== expectedHost) return false;
    if (port && port !== expectedPort) return false;
    return true;
}

function ipv4ToInt(ip) {
    const clean = String(ip || '').replace(/^\[|\]$/g, '').replace(/^::ffff:/, '');
    const parts = clean.split('.');
    if (parts.length !== 4) return null;
    const nums = parts.map(p => Number(p));
    if (nums.some(v => !Number.isInteger(v) || v < 0 || v > 255)) return null;
    return nums.reduce((acc, part) => (acc << 8) + part, 0) >>> 0;
}

function isIpInCidr(ip, cidr) {
    if (cidr.includes(':') || net.isIP(ip) === 6) {
        return isIpInCidrV6(ip, cidr);
    }
    
    const [network, prefixLengthStr] = String(cidr).split('/');
    const prefixLength = Number(prefixLengthStr);
    if (!Number.isInteger(prefixLength) || prefixLength < 0 || prefixLength > 32) return false;
    const ipNum = ipv4ToInt(ip);
    const netNum = ipv4ToInt(network);
    if (ipNum === null || netNum === null) return false;
    const mask = prefixLength === 0 ? 0 : ((0xffffffff << (32 - prefixLength)) >>> 0);
    return (ipNum & mask) === (netNum & mask);
}

function isTrustedProxy(ip) {
    const clean = String(ip || '').replace(/^\[|\]$/g, '').replace(/^::ffff:/, '');
    return TRUSTED_PROXY_CIDRS.some(cidr => isIpInCidr(clean, cidr));
}

function getClientIP(req) {
    const remote = (req.socket && req.socket.remoteAddress) || req.ip || 'unknown';
    const forwarded = req.headers['x-forwarded-for'];
    if (typeof forwarded === 'string' && forwarded.trim() && isTrustedProxy(remote)) {
        const values = forwarded.split(',').map(v => v.trim()).filter(Boolean);
        const last = values[values.length - 1];
        if (last) return last;
    }
    return remote;
}

function requireAdminToken(req, res, next) {
    if (!ADMIN_TOKEN) {
        logger.warn({ path: req.path, ip: req.clientIP }, 'admin_route_missing_secret');
        return res.status(500).json({ error: 'Admin authentication is not configured' });
    }

    const token = req.get('x-admin-token');
    if (!token || !safeEqual(token, ADMIN_TOKEN)) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    next();
}

async function getCountryCode(req) {
    let ip = getClientIP(req);
    // Use full isReservedIp check instead of partial list
    const normalized = ip.replace(/^\[|\]$/g, '').replace(/^::ffff:/, '');
    if (isReservedIp(normalized)) return 'LOCAL';
    
    const cached = geoCache.get(ip);
    if (cached) return cached;

    const url = GEO_API_URL.replace('{ip}', ip);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 2500);

    try {
        const res = await fetch(url, {
            signal: controller.signal,
            headers: { 'User-Agent': 'redirect-service/1.0' }
        });
        if (res.ok) {
            const cc = (await res.text()).trim().toUpperCase();
            geoCache.set(ip, cc || 'XX');
            return cc || 'XX';
        }
        return 'XX';
    } catch (e) {
        logger.warn({ ip, err: e && e.message ? e.message : String(e) }, 'geo_lookup_failed');
        return 'XX';
    } finally {
        clearTimeout(timer);
    }
}

function checkCreationRateLimit(ip) {
    const now = Date.now();
    const key = String(ip || 'unknown');
    const entry = linkCreationRate.get(key);

    if (!entry || now - entry.windowStart > CREATION_WINDOW_MS) {
        linkCreationRate.set(key, { count: 1, windowStart: now });
        return true;
    }

    if (entry.count >= CREATION_LIMIT_PER_IP) {
        return false;
    }

    entry.count++;
    return true;
}

// ====================== FINGERPRINT ROUTES ======================
app.post('/api/fingerprint', async (req, res) => {
    if (!ENABLE_FINGERPRINTING) {
        return res.status(403).json({ error: 'Fingerprinting disabled' });
    }
    
    const body = req.body || {};
    const { token, fingerprint } = body;
    
    // Validate token - must be 32 character hex (challenge ID)
    if (!token || !/^[0-9a-f]{32}$/.test(String(token))) {
        return res.status(400).json({ error: 'Invalid token' });
    }
    
    // Validate fingerprint data
    if (!fingerprint || typeof fingerprint !== 'object' || Array.isArray(fingerprint)) {
        return res.status(400).json({ error: 'fingerprint data required' });
    }
    
    // Rate limit per IP
    const ip = req.clientIP;
    const now = Date.now();
    const rateKey = String(ip || 'unknown');
    const rateEntry = fingerprintRateLimit.get(rateKey);
    
    if (rateEntry && now - rateEntry.windowStart < 60000) {
        if (rateEntry.count >= FINGERPRINT_RATE_LIMIT) {
            return res.status(429).json({ error: 'Rate limit exceeded' });
        }
        rateEntry.count++;
    } else {
        fingerprintRateLimit.set(rateKey, { count: 1, windowStart: now });
    }
    
    // Whitelist and cap fingerprint fields
    const allowedFields = [
        'screenResolution', 'colorDepth', 'pixelRatio', 'timezone', 'timezoneOffset',
        'language', 'languages', 'platform', 'hardwareConcurrency', 'deviceMemory',
        'webglVendor', 'webglRenderer', 'canvasFingerprint', 'audioFingerprint',
        'fontsFingerprint', 'plugins', 'touchSupport', 'insecure'
    ];
    
    const capped = {};
    for (const field of allowedFields) {
        if (fingerprint[field] !== undefined) {
            const value = fingerprint[field];
            if (typeof value === 'string') {
                capped[field] = value.slice(0, MAX_FP_FIELD);
            } else if (typeof value === 'number' || typeof value === 'boolean') {
                capped[field] = value;
            } else {
                capped[field] = String(value).slice(0, MAX_FP_FIELD);
            }
        }
    }
    
    const sig = analyzer.analyze(req.headersDict, ip);
    const fingerprinter = new DeviceFingerprinter();
    const fingerprintId = fingerprinter.generateFingerprintId(req, capped);
    
    try {
        await fingerprinter.saveFingerprint(
            fingerprintId,
            token,
            ip,
            req.headers['user-agent'] || 'unknown',
            capped,
            sig
        );
        
        // Don't leak verdict back to client
        res.json({ 
            success: true, 
            fingerprintId
        });
    } catch (error) {
        logger.error({ error: error.message }, 'fingerprint_save_failed');
        res.status(500).json({ error: 'Failed to save fingerprint' });
    }
});

app.get('/api/device-stats', requireAdminToken, async (req, res) => {
    const { code } = req.query;
    const fingerprinter = new DeviceFingerprinter();
    
    try {
        const stats = await fingerprinter.getDeviceStats(code || null);
        res.json({
            success: true,
            stats,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        logger.error({ error: error.message }, 'device_stats_failed');
        res.status(500).json({ error: 'Failed to get device stats' });
    }
});

app.get('/api/fingerprint/:id', requireAdminToken, async (req, res) => {
    const fingerprinter = new DeviceFingerprinter();
    
    try {
        const fingerprint = await fingerprinter.getFingerprintStats(req.params.id);
        if (!fingerprint) {
            return res.status(404).json({ error: 'Fingerprint not found' });
        }
        res.json({
            success: true,
            fingerprint
        });
    } catch (error) {
        logger.error({ error: error.message }, 'fingerprint_fetch_failed');
        res.status(500).json({ error: 'Failed to get fingerprint' });
    }
});

app.get('/api/click-events', requireAdminToken, async (req, res) => {
    const { code, limit = 100 } = req.query;
    const fingerprinter = new DeviceFingerprinter();
    
    try {
        const events = await fingerprinter.getClickEvents(code || null, parseInt(limit, 10));
        res.json({
            success: true,
            events: events || [],
            count: events ? events.length : 0
        });
    } catch (error) {
        logger.error({ error: error.message }, 'click_events_fetch_failed');
        res.status(500).json({ error: 'Failed to get click events' });
    }
});

// ====================== APPLICATION SETUP ======================
dbInstance = new RedirectDatabase(DB_PATH);
const db = dbInstance;
const analyzer = new BehavioralAnalyzer();
const challengeEngine = new ChallengeEngine();
const fingerprinter = new DeviceFingerprinter();

// ====================== MIDDLEWARE ======================
app.use((req, res, next) => {
    req.requestId = uuidv4();
    res.setHeader('X-Request-ID', req.requestId);
    res.locals.nonce = crypto.randomBytes(16).toString('hex');
    req.clientIP = getClientIP(req);
    req.headersDict = req.headers;

    if (!validateHostHeader(req) && req.path !== '/telegram/webhook') {
        return res.status(400).json({ error: 'Invalid Host header' });
    }

    next();
});

app.use(compression());
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", (req, res) => `'nonce-${res.locals.nonce || ''}'`],
            styleSrc: ["'self'", "'unsafe-inline'"],
            connectSrc: ["'self'"],
            formAction: ["'self'"],
            frameAncestors: ["'none'"],
            baseUri: ["'self'"],
            objectSrc: ["'none'"],
        }
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    xssFilter: true,
    noSniff: true,
    xFrameOptions: 'DENY'
}));

app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));

const asyncHandler = (fn) => (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
};

// ====================== TELEGRAM WEBHOOK ROUTE ======================
let lastTelegramUpdateId = null;

app.post('/telegram/webhook', async (req, res) => {
    let body = null;
    
    if (!ENABLE_TELEGRAM || !telegramBot) {
        return res.status(403).send('Telegram disabled');
    }

    const secretHeader = req.get('x-telegram-bot-api-secret-token');
    if (!TELEGRAM_WEBHOOK_SECRET || secretHeader !== TELEGRAM_WEBHOOK_SECRET) {
        logger.warn({ ip: req.clientIP, path: req.path }, 'telegram_webhook_secret_mismatch');
        return res.send('OK');
    }
    
    try {
        body = req.body || {};
        let updateId = body.update_id !== undefined ? String(body.update_id) : null;
        
        // Duplicate/stale handling
        if (updateId) {
            if (recentUpdateIds.has(updateId)) {
                return res.send('OK');
            }
            if (lastTelegramUpdateId !== null && parseInt(updateId) < lastTelegramUpdateId) {
                logger.info({ updateId }, 'telegram_webhook_stale_dropped');
                return res.send('OK');
            }
        }
        
        const senderChat = body.callback_query?.message?.chat?.id 
            ?? body.message?.chat?.id 
            ?? body.channel_post?.chat?.id;
        
        if (senderChat !== undefined && !isTelegramChatAuthorized(senderChat)) {
            logger.warn({ chatId: senderChat }, 'telegram_unauthorized_chat_dropped');
            return res.send('OK');
        }
        
        // ====== CALLBACK QUERY BRANCH ======
        if (body.callback_query) {
            const query = body.callback_query;
            const data = query.data;
            const chatId = query.message?.chat?.id;
            
            if (!chatId || !isTelegramChatAuthorized(chatId)) {
                return res.send('OK');
            }
            
            try {
                if (data === 'stats') {
                    const stats = await db.getStats();
                    await telegramBot.sendMessage(chatId, formatStatsMessage(stats), { parseMode: 'Markdown' });
                } else if (data === 'recent_blocks') {
                    const recentBlocks = await db.getRecentBotBlocks(10);
                    if (recentBlocks.length === 0) {
                        await telegramBot.sendMessage(chatId, 'No recent bot blocks 🎉');
                    } else {
                        let msg = '🚫 *Recent Bot Blocks*\n\n';
                        recentBlocks.forEach((block, i) => {
                            msg += `${i+1}. \`${escapeTelegramMarkdown(block.code)}\` - ${escapeTelegramMarkdown(block.verdict)} (${(block.score * 100).toFixed(0)}%)\n`;
                        });
                        await telegramBot.sendMessage(chatId, msg, { parseMode: 'Markdown' });
                    }
                } else if (data === 'reset') {
                    await telegramBot.sendMessage(chatId, '🔄 Service is healthy and running');
                } else if (data === 'help') {
                    await telegramBot.sendMessage(chatId, formatTelegramHelpMessage(), { parseMode: 'Markdown' });
                } else if (data === 'fingerprints' && ENABLE_FINGERPRINTING) {
                    const stats = await fingerprinter.getDeviceStats();
                    let msg = '🔍 *Device Fingerprinting Stats*\n\n';
                    if (stats.devices && stats.devices.length > 0) {
                        msg += '*Device Types:*\n';
                        stats.devices.forEach(d => {
                            msg += `• ${d.device_type}: ${d.count}\n`;
                        });
                        msg += '\n*Browsers:*\n';
                        stats.browsers.forEach(b => {
                            msg += `• ${b.browser_name}: ${b.count}\n`;
                        });
                        msg += '\n*OS:*\n';
                        stats.os.forEach(o => {
                            msg += `• ${o.os_name}: ${o.count}\n`;
                        });
                        if (stats.bots) {
                            const botCount = stats.bots.find(b => b.is_bot === 1)?.count || 0;
                            const humanCount = stats.bots.find(b => b.is_bot === 0)?.count || 0;
                            msg += `\n*Bot/Human:*\n• Bot: ${botCount}\n• Human: ${humanCount}`;
                        }
                    } else {
                        msg += 'No fingerprint data collected yet.';
                    }
                    await telegramBot.sendMessage(chatId, msg, { parseMode: 'Markdown' });
                } else if (data === 'fingerprints' && !ENABLE_FINGERPRINTING) {
                    await telegramBot.sendMessage(chatId, '🔍 *Fingerprinting is disabled*', { parseMode: 'Markdown' });
                }
                
                await telegramBot.answerCallbackQuery(query.id).catch(err =>
                    logger.warn({ err: err.message }, 'tg_answer_callback_failed')
                );
            } catch (err) {
                logger.error({ error: err.message }, 'telegram_callback_error');
                await telegramBot.answerCallbackQuery(query.id).catch(() => {});
                
                // CRITICAL: Delete from recent update IDs and return 500 for retry
                if (body && body.update_id !== undefined) {
                    recentUpdateIds.delete(String(body.update_id));
                }
                return res.status(500).send('Error'); // Do NOT advance update ID
            }
            
            // Only advance update ID on success
            if (updateId) {
                lastTelegramUpdateId = parseInt(updateId);
            }
            return res.send('OK');
        }
        
        // ====== MESSAGE BRANCH ======
        if (body.message && body.message.text) {
            const chatId = body.message.chat?.id;
            
            // Guard against malformed updates
            if (!chatId) {
                logger.warn({ body: JSON.stringify(body).slice(0, 200) }, 'telegram_message_missing_chat');
                return res.send('OK');
            }
            
            if (!isTelegramChatAuthorized(chatId)) {
                return res.send('OK');
            }
            
            const text = body.message.text;
            const command = text.split('@')[0].trim();
            
            try {
                if (command === '/start') {
                    await sendTelegramWelcomeMessage(chatId);
                } else if (command === '/help') {
                    await telegramBot.sendMessage(chatId, formatTelegramHelpMessage(), {
                        parseMode: 'Markdown',
                        reply_markup: getInlineKeyboard().reply_markup
                    });
                } else if (command === '/stats') {
                    const stats = await db.getStats();
                    await telegramBot.sendMessage(chatId, formatStatsMessage(stats), { parseMode: 'Markdown' });
                } else if (command === '/recent') {
                    const recentBlocks = await db.getRecentBotBlocks(10);
                    if (recentBlocks.length === 0) {
                        await telegramBot.sendMessage(chatId, 'No recent bot blocks 🎉');
                    } else {
                        let msg = '🚫 *Recent Bot Blocks*\n\n';
                        recentBlocks.forEach((block, i) => {
                            msg += `${i+1}. \`${escapeTelegramMarkdown(block.code)}\` - ${escapeTelegramMarkdown(block.verdict)} (${(block.score * 100).toFixed(0)}%)\n`;
                        });
                        await telegramBot.sendMessage(chatId, msg, { parseMode: 'Markdown' });
                    }
                } else if (command === '/ping') {
                    await telegramBot.sendMessage(chatId, '🏓 Pong! Service is alive ✅');
                } else if (command === '/fingerprints' && ENABLE_FINGERPRINTING) {
                    const stats = await fingerprinter.getDeviceStats();
                    let msg = '🔍 *Device Fingerprinting Stats*\n\n';
                    if (stats.devices && stats.devices.length > 0) {
                        msg += '*Device Types:*\n';
                        stats.devices.forEach(d => {
                            msg += `• ${d.device_type}: ${d.count}\n`;
                        });
                        msg += '\n*Browsers:*\n';
                        stats.browsers.forEach(b => {
                            msg += `• ${b.browser_name}: ${b.count}\n`;
                        });
                        msg += '\n*OS:*\n';
                        stats.os.forEach(o => {
                            msg += `• ${o.os_name}: ${o.count}\n`;
                        });
                        if (stats.bots) {
                            const botCount = stats.bots.find(b => b.is_bot === 1)?.count || 0;
                            const humanCount = stats.bots.find(b => b.is_bot === 0)?.count || 0;
                            msg += `\n*Bot/Human:*\n• Bot: ${botCount}\n• Human: ${humanCount}`;
                        }
                    } else {
                        msg += 'No fingerprint data collected yet.';
                    }
                    await telegramBot.sendMessage(chatId, msg, { parseMode: 'Markdown' });
                } else if (command === '/fingerprints' && !ENABLE_FINGERPRINTING) {
                    await telegramBot.sendMessage(chatId, '🔍 *Fingerprinting is disabled*', { parseMode: 'Markdown' });
                } else if (command.startsWith('/shorten') || command.startsWith('/bulk') || 
                           command.startsWith('/mylinks') || command.startsWith('/delete') || 
                           command.startsWith('/info')) {
                    await telegramBot.sendMessage(chatId, `
❌ *Command Disabled for Security*

Link management commands are not available via Telegram.
Please use the web interface with admin authentication.
                    `, { parseMode: 'Markdown' });
                }
            } catch (err) {
                logger.error({ error: err.message, command }, 'telegram_message_error');
                
                // Delete from recent update IDs and return 500 for retry
                if (body && body.update_id !== undefined) {
                    recentUpdateIds.delete(String(body.update_id));
                }
                return res.status(500).send('Error');
            }
            
            if (updateId) {
                lastTelegramUpdateId = parseInt(updateId);
            }
        }
        
        res.send('OK');
    } catch (error) {
        if (body && body.update_id !== undefined) {
            recentUpdateIds.delete(String(body.update_id));
        }
        logger.error({ error: error.message }, 'Telegram webhook error');
        res.status(500).send('Error');
    }
});

// ====================== TELEGRAM API ROUTES ======================
app.get('/telegram/send', requireAdminToken, async (req, res) => {
    const { message } = req.query;
    if (!ENABLE_TELEGRAM) {
        return res.status(403).json({ error: 'Telegram disabled' });
    }
    
    if (!message) {
        return res.status(400).json({ error: 'Message required' });
    }
    
    await sendTelegramMessage(message);
    res.json({ success: true, message: 'Sent' });
});

app.get('/telegram/stats', requireAdminToken, async (req, res) => {
    if (!ENABLE_TELEGRAM) {
        return res.status(403).json({ error: 'Telegram disabled' });
    }
    
    const stats = await db.getStats();
    await sendTelegramMessage(formatStatsMessage(stats), 'Markdown');
    res.json({ success: true });
});

app.get('/telegram/health', requireAdminToken, async (req, res) => {
    if (!ENABLE_TELEGRAM) {
        return res.json({ enabled: false });
    }
    
    try {
        const me = await telegramBot.getMe();
        res.json({
            enabled: true,
            bot: me.username,
            chatId: TELEGRAM_CHAT_ID,
            webhook: TELEGRAM_WEBHOOK_URL || 'Not set'
        });
    } catch (error) {
        res.status(500).json({
            enabled: true,
            error: error.message
        });
    }
});

app.get('/telegram/commands', requireAdminToken, async (req, res) => {
    if (!ENABLE_TELEGRAM) {
        return res.status(403).json({ error: 'Telegram disabled' });
    }
    
    const commands = [
        { command: 'stats', description: 'View service statistics' },
        { command: 'recent', description: 'Show recent bot blocks' },
        { command: 'ping', description: 'Check if service is alive' },
        { command: 'help', description: 'Show help' }
    ];
    
    if (ENABLE_FINGERPRINTING) {
        commands.push({ command: 'fingerprints', description: 'Show device fingerprinting stats' });
    }
    
    res.json({ commands });
});

// ====================== ROUTES ======================

// Health check
app.get(['/ping', '/health', '/healthz'], (req, res) => {
    res.json({ 
        ok: true, 
        botDetection: 'enabled', 
        version: '4.7',
        telegram: ENABLE_TELEGRAM ? 'enabled' : 'disabled',
        fingerprinting: ENABLE_FINGERPRINTING ? 'enabled' : 'disabled'
    });
});

// Bot stats
app.get('/api/bot-stats', requireAdminToken, async (req, res) => {
    const stats = await db.getStats();
    res.json({
        total_redirects: stats.redirects || 0,
        total_clicks: stats.total_clicks || 0,
        bot_blocks: stats.blocks || 0,
        challenges: stats.challenges || 0,
        decoys: stats.decoys || 0,
        telegram: ENABLE_TELEGRAM ? 'enabled' : 'disabled',
        fingerprinting: ENABLE_FINGERPRINTING ? 'enabled' : 'disabled',
        timestamp: new Date().toISOString()
    });
});

// Challenge verification - duration now optional
app.post('/verify-challenge', async (req, res) => {
    const { challenge_id, nonce, duration } = req.body;

    if (!challenge_id || nonce === undefined) {
        return res.status(400).json({
            ok: false,
            verified: false,
            error: 'challenge_id and nonce are required'
        });
    }

    const verified = challengeEngine.verify(
        challenge_id,
        parseInt(nonce, 10),
        duration !== undefined ? parseInt(duration, 10) : undefined,
        req.clientIP,
        req.headers['user-agent'] || ''
    );

    res.json({ ok: true, verified });
});

// Analytics
app.get('/stats/:code', requireAdminToken, async (req, res) => {
    const code = req.params.code;
    
    let entry = await db.getRedirect(code);
    if (!entry) {
        const jsonEntry = getLink(code);
        if (jsonEntry) {
            return res.json({
                code,
                original_url: jsonEntry.originalUrl,
                created_at: jsonEntry.createdAt,
                total_clicks: jsonEntry.clicks || 0,
                unique_visitors: jsonEntry.uniqueVisitors || 0,
                last_clicked: jsonEntry.lastClicked || null,
            });
        }
        return res.status(404).json({ error: 'Code not found' });
    }

    res.json({
        code: entry.code,
        original_url: entry.target_url,
        created_at: entry.created_at,
        total_clicks: entry.clicks || 0,
        unique_visitors: entry.unique_visitors || 0,
        last_clicked: entry.last_clicked,
        expires_at: entry.expires_at
    });
});

// ====================== CREATE SHORT LINK ======================
app.get('/shorten', asyncHandler(async (req, res) => {
    const { url, alias, expiresIn, campaign_id } = req.query;
    const ip = req.clientIP;

    if (!url) {
        return res.status(400).json({ error: 'Missing "url" parameter' });
    }

    const parsedExpiry = parseExpirySeconds(expiresIn);
    if (expiresIn !== undefined && expiresIn !== null && expiresIn !== '' && parsedExpiry === null) {
        return res.status(400).json({ error: 'Invalid expiresIn value - must be a positive number in seconds' });
    }

    if (!checkCreationRateLimit(ip)) {
        return res.status(429).json({ 
            error: 'Rate limit exceeded for link creation',
            retryAfter: Math.ceil(CREATION_WINDOW_MS / 1000)
        });
    }

    const stats = await db.getStats();
    if (stats.redirects >= MAX_TOTAL_LINKS) {
        return res.status(503).json({ error: 'Service at maximum link capacity' });
    }

    const normalizedCampaignId = normalizeCampaignId(campaign_id);
    if (campaign_id && !normalizedCampaignId) {
        return res.status(400).json({ error: 'Invalid campaign_id format. Use letters, numbers, underscores, or dashes only.' });
    }

    const targetUrl = String(url).trim();
    if (!(await isAllowedTarget(targetUrl))) {
        return res.status(400).json({ error: 'Invalid or disallowed redirect target. HTTPS only, no localhost/private/link-local/metadata targets.' });
    }

    let code;
    if (alias) {
        if (!/^[A-Za-z0-9_-]{3,50}$/.test(alias)) {
            return res.status(400).json({ error: 'Invalid alias format' });
        }
        const existing = await db.getRedirect(alias);
        if (existing) {
            return res.status(409).json({ error: 'Alias already in use' });
        }
        code = alias;
    } else {
        let attempts = 0;
        do {
            code = generateShortCode(6);
            attempts++;
        } while (await db.getRedirect(code) && attempts < 10);
    }

    const expiresAt = parsedExpiry !== null ? new Date(Date.now() + parsedExpiry * 1000).toISOString() : null;
    await db.saveRedirect(code, targetUrl, expiresAt, normalizedCampaignId);

    saveLink(code, {
        originalUrl: targetUrl,
        createdAt: Date.now(),
        clicks: 0,
        uniqueVisitors: 0,
        campaignId: normalizedCampaignId
    });

    if (ENABLE_TELEGRAM) {
        const stats = await db.getStats();
        if (stats.redirects % 10 === 0) {
            const telegramMessage = `
📊 *Link Creation Summary*

📋 *Latest Code:* \`${escapeTelegramMarkdown(code)}\`
🔗 *Short URL:* ${BASE_URL}/${escapeTelegramMarkdown(code)}
📅 *Created:* ${new Date().toISOString()}
📈 *Total Links:* ${stats.redirects}
            `;
            await sendTelegramMessage(telegramMessage);
        }
    }

    res.status(201).json({
        success: true,
        code,
        short_url: `${BASE_URL}/${code}`,
        original_url: targetUrl,
        expires_at: expiresAt,
        campaign_id: normalizedCampaignId
    });
}));

app.post('/shorten', asyncHandler(async (req, res) => {
    const { url, alias, expiresIn, campaign_id } = req.body;
    const ip = req.clientIP;

    if (!url) {
        return res.status(400).json({ error: 'Missing "url" parameter' });
    }

    const parsedExpiry = parseExpirySeconds(expiresIn);
    if (expiresIn !== undefined && expiresIn !== null && expiresIn !== '' && parsedExpiry === null) {
        return res.status(400).json({ error: 'Invalid expiresIn value - must be a positive number in seconds' });
    }

    if (!checkCreationRateLimit(ip)) {
        return res.status(429).json({ 
            error: 'Rate limit exceeded for link creation',
            retryAfter: Math.ceil(CREATION_WINDOW_MS / 1000)
        });
    }

    const stats = await db.getStats();
    if (stats.redirects >= MAX_TOTAL_LINKS) {
        return res.status(503).json({ error: 'Service at maximum link capacity' });
    }

    const normalizedCampaignId = normalizeCampaignId(campaign_id);
    if (campaign_id && !normalizedCampaignId) {
        return res.status(400).json({ error: 'Invalid campaign_id format. Use letters, numbers, underscores, or dashes only.' });
    }

    const targetUrl = String(url).trim();
    if (!(await isAllowedTarget(targetUrl))) {
        return res.status(400).json({ error: 'Invalid or disallowed redirect target. HTTPS only, no localhost/private/link-local/metadata targets.' });
    }

    let code;
    if (alias) {
        if (!/^[A-Za-z0-9_-]{3,50}$/.test(alias)) {
            return res.status(400).json({ error: 'Invalid alias format' });
        }
        const existing = await db.getRedirect(alias);
        if (existing) {
            return res.status(409).json({ error: 'Alias already in use' });
        }
        code = alias;
    } else {
        let attempts = 0;
        do {
            code = generateShortCode(6);
            attempts++;
        } while (await db.getRedirect(code) && attempts < 10);
    }

    const expiresAt = parsedExpiry !== null ? new Date(Date.now() + parsedExpiry * 1000).toISOString() : null;
    await db.saveRedirect(code, targetUrl, expiresAt, normalizedCampaignId);

    saveLink(code, {
        originalUrl: targetUrl,
        createdAt: Date.now(),
        clicks: 0,
        uniqueVisitors: 0,
        campaignId: normalizedCampaignId
    });

    if (ENABLE_TELEGRAM) {
        const stats = await db.getStats();
        if (stats.redirects % 10 === 0) {
            const telegramMessage = `
📊 *Link Creation Summary*

📋 *Latest Code:* \`${escapeTelegramMarkdown(code)}\`
🔗 *Short URL:* ${BASE_URL}/${escapeTelegramMarkdown(code)}
📅 *Created:* ${new Date().toISOString()}
📈 *Total Links:* ${stats.redirects}
            `;
            await sendTelegramMessage(telegramMessage);
        }
    }

    res.status(201).json({
        success: true,
        code,
        short_url: `${BASE_URL}/${code}`,
        original_url: targetUrl,
        expires_at: expiresAt,
        campaign_id: normalizedCampaignId
    });
}));

// ====================== REDIRECT WITH BOT DETECTION ======================
app.get('/:code', asyncHandler(async (req, res) => {
    const code = req.params.code;
    const ip = req.clientIP;
    const country = await getCountryCode(req);

    const sig = analyzer.analyze(req.headersDict, ip);
    
    let entry = await db.getRedirect(code);
    let isJsonFallback = false;
    
    if (!entry) {
        const jsonEntry = getLink(code);
        if (jsonEntry) {
            isJsonFallback = true;
            entry = {
                code: code,
                target_url: jsonEntry.originalUrl,
                created_at: new Date(jsonEntry.createdAt).toISOString(),
                clicks: jsonEntry.clicks || 0,
                unique_visitors: jsonEntry.uniqueVisitors || 0,
                last_clicked: jsonEntry.lastClicked ? new Date(jsonEntry.lastClicked).toISOString() : null,
                expires_at: jsonEntry.expiresAt ? new Date(jsonEntry.expiresAt).toISOString() : null
            };
            
            // JSON entries are validated at startup, but keep this for safety
            if (!(await isAllowedTarget(entry.target_url))) {
                logger.warn({ code, target: entry.target_url }, 'legacy_json_invalid_target');
                return res.redirect(BOT_URLS[Math.floor(Math.random() * BOT_URLS.length)]);
            }
        }
    }

    if (!entry) {
        logger.warn({ code, ip, country }, 'code_not_found');
        return res.status(404).send('Short URL not found');
    }

    const cleanShortUrl = getCleanShortUrl(code);
    const requestedPath = req.path || '/';
    const shouldNormalizeUrl = Object.keys(req.query).length > 0 || requestedPath !== `/${code}`;

    if (shouldNormalizeUrl) {
        logger.info({ code, ip, country, requestedPath, query: req.query }, 'short_url_normalized');
        return res.redirect(302, cleanShortUrl);
    }

    if (entry.expires_at && new Date(entry.expires_at) < new Date()) {
        await db.deleteLink(code);
        deleteLink(code);
        return res.status(410).send('Link has expired');
    }

    // ====== HANDLE BOT VERDICTS ======
    if (sig.verdict === 'block') {
        await db.logBotBlock(ip, req.headers['user-agent'], sig, code);
        return res.status(403).send('Access denied');
    }

    if (sig.verdict === 'rate_limit') {
        const resetTime = sig.environmental?.rateLimit?.resetAt || Date.now() + 60000;
        const retryAfter = Math.ceil((resetTime - Date.now()) / 1000);
        res.setHeader('Retry-After', retryAfter);
        return res.status(429).json({ 
            error: 'Rate limit exceeded',
            retryAfter: retryAfter
        });
    }

    if (sig.verdict === 'decoy') {
        await db.logBotBlock(ip, req.headers['user-agent'], sig, code);
        return res.redirect(BOT_URLS[Math.floor(Math.random() * BOT_URLS.length)]);
    }

    if (sig.verdict === 'challenge') {
        const session = verifySignedSession(req);
        if (!session || !session.solved) {
            if (!session) {
                issueSignedSession(req, res);
            }
            await db.logBotBlock(ip, req.headers['user-agent'], sig, code);
            
            if (ENABLE_TELEGRAM) {
                const alertKey = `${code}:${ip}`;
                const now = Date.now();
                const alertUntil = botAlertCooldowns.get(alertKey) || 0;
                if (alertUntil <= now) {
                    rememberBotAlert(alertKey);
                    const message = formatBotDetectionMessage(code, ip, country, sig, entry.target_url);
                    await sendTelegramMessage(message, 'Markdown').catch(() => {});
                }
            }
            
            const { html } = challengeEngine.createChallenge(entry.target_url, sig.score, res.locals.nonce);
            return res.send(html);
        }
    }

    if (sig.verdict === 'slow_down') {
        await new Promise(resolve => setTimeout(resolve, 250));
    }

    // ====== COUNT CLICKS ======
    if (!isJsonFallback) {
        await db.incrementClicks(code);
        const visitorId = ip;
        if (!await db.hasVisitor(code, visitorId)) {
            await db.addVisitor(code, visitorId);
        }
    } else {
        const jsonEntry = getLink(code);
        if (jsonEntry) {
            jsonEntry.clicks = (jsonEntry.clicks || 0) + 1;
            jsonEntry.lastClicked = Date.now();
            const visitorId = ip;
            if (!hasVisitor(code, visitorId)) {
                addVisitor(code, visitorId);
                jsonEntry.uniqueVisitors = (jsonEntry.uniqueVisitors || 0) + 1;
            }
            saveLink(code, jsonEntry);
        }
    }

    // ====== CACHE CHECK ======
    const cacheKey = `redirect:${code}`;
    const cachedTarget = responseCache.get(cacheKey);
    if (cachedTarget && sig.verdict !== 'slow_down') {
        logger.info({ code, ip, country, target: cachedTarget, cached: true }, 'redirect_cached');
        return res.redirect(302, cachedTarget);
    }

    responseCache.set(cacheKey, entry.target_url);

    // ====== MILESTONE NOTIFICATION ======
    const newClickCount = (entry.clicks || 0) + 1;
    if (ENABLE_TELEGRAM && newClickCount % 100 === 0) {
        await sendTelegramMessage(`
🎯 *Milestone Reached!*

📋 *Code:* \`${escapeTelegramMarkdown(code)}\`
👆 *Total Clicks:* ${newClickCount}
🔗 *Target:* ${escapeTelegramMarkdown(entry.target_url.substring(0, 40))}...
🕐 *Last Clicked:* ${new Date().toISOString()}
        `);
    }

    logger.info({ code, ip, country, target: entry.target_url }, 'redirect');
    res.redirect(302, entry.target_url);
}));

// ====================== CLEANUP JOB ======================
setInterval(async () => {
    const now = new Date();
    const codes = await db.getRedirectsExpired(now);
    for (const code of codes) {
        await db.deleteLink(code);
        deleteLink(code);
        logger.info({ code }, 'expired_link_removed');
    }
}, 3600000);

// ====================== CATCH-ALL ======================
app.use((req, res) => {
    const ip = req.clientIP || 'unknown';
    logger.warn({ ip, path: req.path, method: req.method }, 'unknown_route');
    res.redirect(BOT_URLS[Math.floor(Math.random() * BOT_URLS.length)]);
});

// ====================== START SERVER ======================
if (require.main === module) {
    app.listen(PORT, '0.0.0.0', () => {
        const cacheStats = responseCache.getStats();
        console.log(`
╔═══════════════════════════════════════════════════════════════════╗
║   🚀 Advanced Anti-Bot Redirect Service v4.7                    ║
╠═══════════════════════════════════════════════════════════════════╣
║   Port: ${String(PORT).padEnd(50)}║
║   Base URL: ${BASE_URL.padEnd(47)}║
║   Database: SQLite + JSON (Dual)                               ║
║   Bot Detection: Multi-Factor v4.7                            ║
║   Fingerprinting: ${ENABLE_FINGERPRINTING ? '✅ Enabled' : '❌ Disabled'.padEnd(25)}║
║   IP Validation: IPv4 + IPv6 + Embedded + Numeric Tricks     ║
║   DNS: Timeout + Semaphore (${MAX_CONCURRENT_DNS_LOOKUPS} concurrent)        ║
║   Rate Limiting: Adaptive + Creation Limits                  ║
║   Telegram: ${ENABLE_TELEGRAM ? '✅ Enabled (Authorized Only)' : '❌ Disabled'.padEnd(25)}║
║   Cache: ${cacheStats.keys > 0 ? 'Warm' : 'Cold'} (${cacheStats.keys} entries)                    ║
║   Protection: Block/Decoy/Challenge/Slow/RateLimit           ║
║   Retention: ${RETENTION_DAYS} days / ${MAX_FINGERPRINT_ROWS} rows cap         ║
╚═══════════════════════════════════════════════════════════════════╝
        `);
    });
}

module.exports = {
    app,
    db,
    analyzer,
    challengeEngine,
    telegramBot,
    fingerprinter,
    getClientIP,
    getCleanShortUrl,
    validateHostHeader,
    isTrustedProxy,
    ipv4ToInt,
    isIpInCidr,
    parseCookies,
    signSessionValue,
    issueSignedSession,
    verifySignedSession,
    isAllowedTarget,
    normalizeCampaignId,
    escapeTelegramMarkdown,
    isTelegramChatAuthorized,
    isReservedIp,
    lookupHost,
    rememberBotAlert,
    rememberUpdateId,
    safeEqual,
    isIpInCidrV6,
    isBotVerdict,
    DeviceFingerprinter
};
