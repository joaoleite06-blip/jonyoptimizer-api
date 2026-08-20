require('dotenv').config();

const express = require('express');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcrypt');
const db = require('./database');

const pendingDiscordLogins = new Map();
const discordTokenCooldowns = new Map();
const app = express();

app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;
const DISCORD_TOKEN_URL = 'https://discord.com/api/oauth2/token';
const DISCORD_USER_URL = 'https://discord.com/api/users/@me';
const DISCORD_LOGIN_EXPIRY_MS = 10 * 60 * 1000;
const DISCORD_AUTHORIZED_EXPIRY_MS = 5 * 60 * 1000;
const DISCORD_TOKEN_COOLDOWN_MS = 30 * 1000;

const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const DISCORD_REDIRECT_URI = process.env.DISCORD_REDIRECT_URI;
const DISCORD_GUILD_ID = process.env.DISCORD_GUILD_ID;
const DISCORD_REQUIRED_ROLE_ID = process.env.DISCORD_REQUIRED_ROLE_ID;

function hasRequiredEnvironmentVariables() {
    return Boolean(
        DISCORD_CLIENT_ID &&
        DISCORD_CLIENT_SECRET &&
        DISCORD_REDIRECT_URI &&
        DISCORD_GUILD_ID &&
        DISCORD_REQUIRED_ROLE_ID
    );
}

function escapeHtml(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function getRetryAfterMs(response, body) {
    const retryAfterHeader = response.headers.get('retry-after');

    if (retryAfterHeader) {
        const seconds = Number(retryAfterHeader);

        if (Number.isFinite(seconds) && seconds > 0) {
            return Math.ceil(seconds * 1000);
        }
    }

    try {
        const data = JSON.parse(body);
        const retryAfterSeconds = Number(data.retry_after);

        if (Number.isFinite(retryAfterSeconds) && retryAfterSeconds > 0) {
            return Math.ceil(retryAfterSeconds * 1000);
        }
    } catch {
        // A resposta pode não ser JSON, por exemplo um erro Cloudflare 1015.
    }

    return DISCORD_TOKEN_COOLDOWN_MS;
}

function getRemainingCooldownMs(requestId) {
    const cooldownUntil = discordTokenCooldowns.get(requestId);

    if (!cooldownUntil) {
        return 0;
    }

    const remainingMs = cooldownUntil - Date.now();

    if (remainingMs <= 0) {
        discordTokenCooldowns.delete(requestId);
        return 0;
    }

    return remainingMs;
}

function sendHtmlPage(res, status, title, heading, message) {
    return res.status(status).send(`
<!doctype html>
<html lang="pt-PT">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>${escapeHtml(title)}</title>
</head>
<body style="font-family: Arial, sans-serif; background: #111827; color: white; text-align: center; padding: 80px 20px;">
    <h1>${escapeHtml(heading)}</h1>
    <p>${escapeHtml(message)}</p>
</body>
</html>
`);
}

async function readDiscordResponse(response, label) {
    const contentType = response.headers.get('content-type') || '';
    const body = await response.text();

    if (!response.ok) {
        const error = new Error(`${label} devolveu HTTP ${response.status}`);
        error.status = response.status;
        error.retryAfterMs = response.status === 429
            ? getRetryAfterMs(response, body)
            : 0;

        console.error(`${label} falhou:`, {
            status: response.status,
            statusText: response.statusText,
            contentType,
            retryAfterMs: error.retryAfterMs,
            body: body.substring(0, 1000)
        });

        throw error;
    }

    if (!contentType.toLowerCase().includes('application/json')) {
        console.error(`${label} devolveu conteúdo não-JSON:`, {
            status: response.status,
            contentType,
            body: body.substring(0, 1000)
        });

        const error = new Error(`${label} devolveu uma resposta não-JSON`);
        error.status = 502;
        throw error;
    }

    try {
        return JSON.parse(body);
    } catch {
        console.error(`${label} devolveu JSON inválido:`, {
            status: response.status,
            contentType,
            body: body.substring(0, 1000)
        });

        const error = new Error(`${label} devolveu JSON inválido`);
        error.status = 502;
        throw error;
    }
}

function cleanupExpiredDiscordLogins() {
    const now = Date.now();

    for (const [requestId, login] of pendingDiscordLogins.entries()) {
        if (now > login.expiresAt) {
            pendingDiscordLogins.delete(requestId);
            discordTokenCooldowns.delete(requestId);
        }
    }

    for (const [requestId, cooldownUntil] of discordTokenCooldowns.entries()) {
        if (now >= cooldownUntil) {
            discordTokenCooldowns.delete(requestId);
        }
    }
}

setInterval(cleanupExpiredDiscordLogins, 60 * 1000).unref();

app.get('/', (req, res) => {
    res.send('API de licenças JonyOptimizer está online.');
});

app.get('/healthz', (req, res) => {
    res.status(200).send('ok');
});

// A app abre este endpoint uma única vez por tentativa de login.
app.get('/api/discord/login/:requestId', (req, res) => {
    if (!hasRequiredEnvironmentVariables()) {
        console.error('Faltam variáveis de ambiente do Discord.');

        return res.status(500).send(
            'A API não está configurada corretamente.'
        );
    }

    const requestId = req.params.requestId;

    if (!requestId || requestId.length < 10) {
        return res.status(400).send('Pedido de login inválido.');
    }

    const state = uuidv4();

    pendingDiscordLogins.set(requestId, {
        state,
        status: 'pending',
        expiresAt: Date.now() + DISCORD_LOGIN_EXPIRY_MS
    });

    discordTokenCooldowns.delete(requestId);

    const scope = encodeURIComponent(
        'identify guilds guilds.members.read'
    );

    const url =
        'https://discord.com/oauth2/authorize' +
        '?client_id=' + encodeURIComponent(DISCORD_CLIENT_ID) +
        '&redirect_uri=' + encodeURIComponent(DISCORD_REDIRECT_URI) +
        '&response_type=code' +
        '&scope=' + scope +
        '&state=' + encodeURIComponent(state);

    return res.redirect(url);
});

// Discord volta aqui depois de o utilizador autorizar.
app.get('/api/discord/callback', async (req, res) => {
    let requestId = null;

    try {
        const { code, state, error } = req.query;

        if (error) {
            console.error('Discord recusou ou cancelou a autorização:', error);

            return sendHtmlPage(
                res,
                400,
                'Autorização cancelada',
                'Autorização Discord cancelada',
                'Volta à aplicação e tenta novamente quando estiveres pronto.'
            );
        }

        if (!hasRequiredEnvironmentVariables()) {
            console.error('Faltam variáveis de ambiente do Discord.');

            return sendHtmlPage(
                res,
                500,
                'Configuração inválida',
                'A API não está configurada',
                'Contacta o administrador da aplicação.'
            );
        }

        const loginEntry = [...pendingDiscordLogins.entries()]
            .find(([, login]) => login.state === state);

        if (!code || !state || !loginEntry) {
            return sendHtmlPage(
                res,
                400,
                'Pedido inválido',
                'Pedido Discord inválido ou expirado',
                'Volta à aplicação e inicia um novo login.'
            );
        }

        requestId = loginEntry[0];
        const pendingLogin = loginEntry[1];

        if (Date.now() > pendingLogin.expiresAt) {
            pendingDiscordLogins.delete(requestId);
            discordTokenCooldowns.delete(requestId);

            return sendHtmlPage(
                res,
                400,
                'Pedido expirado',
                'Pedido Discord expirado',
                'Volta à aplicação e tenta novamente.'
            );
        }

        if (pendingLogin.status === 'processing') {
            return sendHtmlPage(
                res,
                409,
                'Pedido em processamento',
                'Este login já está a ser validado',
                'Aguarda alguns segundos e volta à aplicação.'
            );
        }

        const cooldownMs = getRemainingCooldownMs(requestId);

        if (cooldownMs > 0) {
            const seconds = Math.ceil(cooldownMs / 1000);

            return sendHtmlPage(
                res,
                429,
                'Aguarda antes de tentar',
                'O Discord limitou temporariamente os pedidos',
                `Aguarda cerca de ${seconds} segundos e inicia um novo login apenas uma vez.`
            );
        }

        pendingLogin.status = 'processing';
        pendingDiscordLogins.set(requestId, pendingLogin);

        const tokenBody = new URLSearchParams({
            client_id: DISCORD_CLIENT_ID,
            client_secret: DISCORD_CLIENT_SECRET,
            grant_type: 'authorization_code',
            code,
            redirect_uri: DISCORD_REDIRECT_URI
        });

        const tokenResponse = await fetch(DISCORD_TOKEN_URL, {
            method: 'POST',
            headers: {
                Accept: 'application/json',
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: tokenBody.toString()
        });

        const tokenData = await readDiscordResponse(
            tokenResponse,
            'Token Discord'
        );

        if (!tokenData.access_token) {
            console.error('Token Discord sem access_token.');

            pendingLogin.status = 'pending';
            pendingDiscordLogins.set(requestId, pendingLogin);

            return sendHtmlPage(
                res,
                400,
                'Token indisponível',
                'Não foi possível obter o token Discord',
                'Volta à aplicação e tenta novamente.'
            );
        }

        const headers = {
            Accept: 'application/json',
            Authorization: 'Bearer ' + tokenData.access_token
        };

        const userResponse = await fetch(DISCORD_USER_URL, { headers });
        const user = await readDiscordResponse(userResponse, 'Perfil Discord');

        const memberResponse = await fetch(
            'https://discord.com/api/users/@me/guilds/' +
            encodeURIComponent(DISCORD_GUILD_ID) +
            '/member',
            { headers }
        );

        if (
            memberResponse.status === 401 ||
            memberResponse.status === 403 ||
            memberResponse.status === 404
        ) {
            const body = await memberResponse.text();

            console.error('Membro Discord sem acesso:', {
                status: memberResponse.status,
                contentType: memberResponse.headers.get('content-type') || '',
                body: body.substring(0, 1000)
            });

            pendingLogin.status = 'pending';
            pendingDiscordLogins.set(requestId, pendingLogin);

            return sendHtmlPage(
                res,
                403,
                'Sem acesso ao servidor',
                'Não tens acesso ao Discord oficial',
                'Confirma que entraste no servidor Discord e volta à aplicação.'
            );
        }

        const member = await readDiscordResponse(
            memberResponse,
            'Membro Discord'
        );

        const hasRequiredRole =
            Array.isArray(member.roles) &&
            member.roles.includes(DISCORD_REQUIRED_ROLE_ID);

        if (!hasRequiredRole) {
            pendingLogin.status = 'pending';
            pendingDiscordLogins.set(requestId, pendingLogin);

            return sendHtmlPage(
                res,
                403,
                'Role necessária em falta',
                'Não tens a role necessária no servidor Discord',
                'Pede acesso ao administrador do servidor e volta à aplicação.'
            );
        }

        pendingDiscordLogins.set(requestId, {
            status: 'authorized',
            discordId: user.id,
            username: user.global_name || user.username,
            expiresAt: Date.now() + DISCORD_AUTHORIZED_EXPIRY_MS
        });

        discordTokenCooldowns.delete(requestId);

        return sendHtmlPage(
            res,
            200,
            'Discord validado',
            'Discord validado com sucesso',
            `Podes fechar esta página e voltar à aplicação JonyOptimizer. Utilizador: ${user.global_name || user.username}`
        );
    } catch (error) {
        const status = error.status || 500;

        console.error('Erro Discord OAuth:', {
            message: error.message,
            status,
            retryAfterMs: error.retryAfterMs || 0,
            stack: error.stack
        });

        if (requestId) {
            const login = pendingDiscordLogins.get(requestId);

            if (login && login.status === 'processing') {
                login.status = 'pending';
                pendingDiscordLogins.set(requestId, login);
            }
        }

        if (status === 429) {
            const waitMs = Math.max(
                error.retryAfterMs || DISCORD_TOKEN_COOLDOWN_MS,
                DISCORD_TOKEN_COOLDOWN_MS
            );

            if (requestId) {
                discordTokenCooldowns.set(requestId, Date.now() + waitMs);
            }

            const seconds = Math.ceil(waitMs / 1000);

            return sendHtmlPage(
                res,
                429,
                'Pedido temporariamente limitado',
                'O Discord limitou temporariamente os pedidos',
                `Aguarda pelo menos ${seconds} segundos. Depois volta à aplicação e inicia apenas um novo login.`
            );
        }

        return sendHtmlPage(
            res,
            status,
            'Erro ao validar Discord',
            'Erro ao validar o Discord',
            'Consulta os logs do servidor ou volta à aplicação e tenta novamente mais tarde.'
        );
    }
});

// A app C# consulta este endpoint a cada dois segundos.
app.get('/api/discord/status/:requestId', (req, res) => {
    const requestId = req.params.requestId;
    const login = pendingDiscordLogins.get(requestId);

    if (!login) {
        return res.json({
            success: false,
            status: 'pending'
        });
    }

    if (Date.now() > login.expiresAt) {
        pendingDiscordLogins.delete(requestId);
        discordTokenCooldowns.delete(requestId);

        return res.json({
            success: false,
            status: 'expired'
        });
    }

    const retryAfterMs = getRemainingCooldownMs(requestId);

    if (retryAfterMs > 0) {
        return res.json({
            success: false,
            status: 'rate_limited',
            retry_after_seconds: Math.ceil(retryAfterMs / 1000)
        });
    }

    if (login.status === 'processing') {
        return res.json({
            success: false,
            status: 'processing'
        });
    }

    if (login.status !== 'authorized') {
        return res.json({
            success: false,
            status: 'pending'
        });
    }

    return res.json({
        success: true,
        status: 'authorized',
        discordId: login.discordId,
        username: login.username
    });
});

// Criar uma licença manualmente.
app.post('/api/licenses/create', (req, res) => {
    try {
        const { discord_id, email, expires_at, max_devices = 1 } = req.body;

        if (!discord_id || !expires_at) {
            return res.status(400).json({
                success: false,
                error: 'discord_id e expires_at são obrigatórios.'
            });
        }

        const licenseKey =
            `OPT-${uuidv4().split('-')[0].toUpperCase()}-` +
            `${uuidv4().split('-')[1].toUpperCase()}`;

        const licenseKeyHash = bcrypt.hashSync(licenseKey, 10);

        let user = db
            .prepare('SELECT * FROM users WHERE discord_id = ?')
            .get(discord_id);

        if (!user) {
            const userId = uuidv4();

            db.prepare(`
                INSERT INTO users (id, discord_id, email)
                VALUES (?, ?, ?)
            `).run(userId, discord_id, email || null);

            user = {
                id: userId,
                discord_id,
                email: email || null
            };
        }

        const licenseId = uuidv4();

        db.prepare(`
            INSERT INTO licenses
            (id, license_key_hash, user_id, expires_at, max_devices)
            VALUES (?, ?, ?, ?, ?)
        `).run(
            licenseId,
            licenseKeyHash,
            user.id,
            expires_at,
            Number(max_devices) || 1
        );

        console.log(`Licença criada: ${licenseKey}`);

        return res.json({
            success: true,
            license_key: licenseKey,
            discord_id,
            expires_at,
            max_devices: Number(max_devices) || 1
        });
    } catch (error) {
        console.error('Erro ao criar licença:', error);

        return res.status(500).json({
            success: false,
            error: 'server_error'
        });
    }
});

// Ativar uma licença num computador.
app.post('/api/activate', (req, res) => {
    try {
        const { license_key, hwid } = req.body;

        if (!license_key || !hwid) {
            return res.status(400).json({
                valid: false,
                reason: 'missing_fields'
            });
        }

        const licenses = db.prepare(`
            SELECT *
            FROM licenses
            WHERE status = 'active'
              AND expires_at > CURRENT_TIMESTAMP
        `).all();

        let license = null;

        for (const currentLicense of licenses) {
            if (bcrypt.compareSync(
                license_key,
                currentLicense.license_key_hash
            )) {
                license = currentLicense;
                break;
            }
        }

        if (!license) {
            return res.status(404).json({
                valid: false,
                reason: 'license_not_found'
            });
        }

        let device = db.prepare(`
            SELECT *
            FROM devices
            WHERE license_id = ?
              AND device_fingerprint = ?
              AND status = 'active'
        `).get(license.id, hwid);

        if (!device) {
            const activeDevices = db.prepare(`
                SELECT COUNT(*) AS count
                FROM devices
                WHERE license_id = ?
                  AND status = 'active'
            `).get(license.id);

            if (activeDevices.count >= license.max_devices) {
                return res.status(403).json({
                    valid: false,
                    reason: 'device_limit'
                });
            }

            const deviceId = uuidv4();

            db.prepare(`
                INSERT INTO devices (id, license_id, device_fingerprint)
                VALUES (?, ?, ?)
            `).run(deviceId, license.id, hwid);

            device = { id: deviceId };
        }

        db.prepare(`
            UPDATE devices
            SET last_seen = CURRENT_TIMESTAMP
            WHERE id = ?
        `).run(device.id);

        const sessionToken = uuidv4();

        const sessionExpiresAt = new Date(
            Date.now() + 7 * 24 * 60 * 60 * 1000
        ).toISOString();

        db.prepare(`
            INSERT INTO sessions
            (id, user_id, device_id, token_hash, expires_at)
            VALUES (?, ?, ?, ?, ?)
        `).run(
            uuidv4(),
            license.user_id,
            device.id,
            sessionToken,
            sessionExpiresAt
        );

        return res.json({
            valid: true,
            session_token: sessionToken,
            expires_at: sessionExpiresAt,
            license: {
                product: license.product_id,
                status: license.status,
                max_devices: license.max_devices
            }
        });
    } catch (error) {
        console.error('Erro de ativação:', error);

        return res.status(500).json({
            valid: false,
            reason: 'server_error'
        });
    }
});

// Validar sessão existente.
app.post('/api/validate', (req, res) => {
    try {
        const { hwid, session_token } = req.body;

        if (!hwid || !session_token) {
            return res.status(400).json({
                valid: false,
                reason: 'missing_fields'
            });
        }

        const activeSession = db.prepare(`
            SELECT
                s.id AS session_id,
                s.device_id,
                l.status AS license_status,
                l.expires_at AS license_expires_at
            FROM sessions s
            JOIN devices d ON d.id = s.device_id
            JOIN licenses l ON l.id = d.license_id
            WHERE s.token_hash = ?
              AND s.expires_at > CURRENT_TIMESTAMP
              AND d.device_fingerprint = ?
              AND d.status = 'active'
        `).get(session_token, hwid);

        if (!activeSession) {
            return res.json({
                valid: false,
                reason: 'invalid_session',
                requires_reactivation: true
            });
        }

        if (
            activeSession.license_status !== 'active' ||
            new Date(activeSession.license_expires_at) <= new Date()
        ) {
            return res.json({
                valid: false,
                reason: 'license_expired',
                requires_reactivation: true
            });
        }

        db.prepare(`
            UPDATE devices
            SET last_seen = CURRENT_TIMESTAMP
            WHERE id = ?
        `).run(activeSession.device_id);

        return res.json({
            valid: true,
            license: {
                product: 'optimizer_pro',
                status: 'active'
            }
        });
    } catch (error) {
        console.error('Erro de validação:', error);

        return res.status(500).json({
            valid: false,
            reason: 'server_error'
        });
    }
});

app.listen(PORT, () => {
    console.log(`API a correr na porta ${PORT}`);
});
