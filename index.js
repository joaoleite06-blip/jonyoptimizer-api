require('dotenv').config();

const express = require('express');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcrypt');
const db = require('./database');

const pendingDiscordLogins = new Map();
const app = express();

app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;

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

async function readDiscordResponse(response, label) {
    const contentType = response.headers.get('content-type') || '';
    const body = await response.text();

    if (!response.ok) {
        console.error(`${label} falhou:`, {
            status: response.status,
            statusText: response.statusText,
            contentType,
            body: body.substring(0, 1000)
        });

        const error = new Error(`${label} devolveu HTTP ${response.status}`);
        error.status = response.status;
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
    } catch (parseError) {
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

app.get('/', (req, res) => {
    res.send('API de licenças JonyOptimizer está online.');
});

app.get('/healthz', (req, res) => {
    res.status(200).send('ok');
});

// A app abre este endpoint no browser.
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
        expiresAt: Date.now() + (10 * 60 * 1000)
    });

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
    try {
        const { code, state, error } = req.query;

        if (error) {
            console.error('Discord recusou ou cancelou a autorização:', error);

            return res.status(400).send(
                'Autorização Discord cancelada ou recusada.'
            );
        }

        if (!hasRequiredEnvironmentVariables()) {
            console.error('Faltam variáveis de ambiente do Discord.');

            return res.status(500).send(
                'A API não está configurada corretamente.'
            );
        }

        const loginEntry = [...pendingDiscordLogins.entries()]
            .find(([, login]) => login.state === state);

        if (!code || !state || !loginEntry) {
            return res.status(400).send(
                'Pedido Discord inválido ou expirado.'
            );
        }

        const requestId = loginEntry[0];
        const pendingLogin = loginEntry[1];

        if (Date.now() > pendingLogin.expiresAt) {
            pendingDiscordLogins.delete(requestId);

            return res.status(400).send(
                'Pedido Discord expirado. Volta à aplicação e tenta novamente.'
            );
        }

        const tokenBody = new URLSearchParams({
            client_id: DISCORD_CLIENT_ID,
            client_secret: DISCORD_CLIENT_SECRET,
            grant_type: 'authorization_code',
            code,
            redirect_uri: DISCORD_REDIRECT_URI
        });

        const tokenResponse = await fetch(
            'https://discord.com/api/oauth2/token',
            {
                method: 'POST',
                headers: {
                    Accept: 'application/json',
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: tokenBody.toString()
            }
        );

        const tokenData = await readDiscordResponse(
            tokenResponse,
            'Token Discord'
        );

        if (!tokenData.access_token) {
            console.error(
                'Token Discord sem access_token:',
                tokenData
            );

            return res.status(400).send(
                'Não foi possível obter o token Discord.'
            );
        }

        const headers = {
            Accept: 'application/json',
            Authorization: 'Bearer ' + tokenData.access_token
        };

        const userResponse = await fetch(
            'https://discord.com/api/users/@me',
            { headers }
        );

        const user = await readDiscordResponse(
            userResponse,
            'Perfil Discord'
        );

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

            return res.status(403).send(
                'Não tens acesso. Primeiro entra no servidor Discord oficial.'
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
            return res.status(403).send(
                'Não tens a role necessária no servidor Discord.'
            );
        }

        pendingDiscordLogins.set(requestId, {
            status: 'authorized',
            discordId: user.id,
            username: user.global_name || user.username,
            expiresAt: Date.now() + (5 * 60 * 1000)
        });

        return res.send(`
<!doctype html>
<html lang="pt-PT">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Discord validado</title>
</head>
<body style="font-family: Arial, sans-serif; background: #111827; color: white; text-align: center; padding: 80px 20px;">
    <h1>Discord validado com sucesso</h1>
    <p>Podes fechar esta página e voltar à aplicação JonyOptimizer.</p>
    <p>Utilizador: ${escapeHtml(user.global_name || user.username)}</p>
</body>
</html>
`);
    } catch (error) {
        console.error('Erro Discord OAuth:', {
            message: error.message,
            status: error.status || 500,
            stack: error.stack
        });

        return res.status(error.status || 500).send(
            'Erro ao validar o Discord. Consulta os logs do servidor.'
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

        return res.json({
            success: false,
            status: 'expired'
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
