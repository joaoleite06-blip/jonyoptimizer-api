require('dotenv').config();

const express = require('express');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcrypt');
const session = require('express-session');
const db = require('./database');
const pendingDiscordLogins = new Map();
const app = express();

app.use(cors());
app.use(express.json());

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 10 * 60 * 1000 // 10 minutos
    }
}));

const PORT = process.env.PORT || 3000;

const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const DISCORD_REDIRECT_URI = process.env.DISCORD_REDIRECT_URI;
const DISCORD_GUILD_ID = process.env.DISCORD_GUILD_ID;
const DISCORD_REQUIRED_ROLE_ID = process.env.DISCORD_REQUIRED_ROLE_ID;

// Página simples para confirmar no browser que a API está online.
app.get('/', (req, res) => {
    res.send('API de licenças JonyOptimizer está online.');
});

// Inicia um login Discord associado a esta abertura da app.
app.get('/api/discord/login/:requestId', (req, res) => {
    const requestId = req.params.requestId;

    if (!requestId || requestId.length < 10) {
        return res.status(400).send('Pedido de login inválido.');
    }

    const state = uuidv4();

    req.session.discordState = state;
    req.session.discordRequestId = requestId;

    const scope = encodeURIComponent('identify guilds guilds.members.read');

    const url =
        'https://discord.com/oauth2/authorize' +
        '?client_id=' + encodeURIComponent(DISCORD_CLIENT_ID) +
        '&redirect_uri=' + encodeURIComponent(DISCORD_REDIRECT_URI) +
        '&response_type=code' +
        '&scope=' + scope +
        '&state=' + encodeURIComponent(state);

    return res.redirect(url);
});

// O Discord redireciona para aqui depois do login
app.get('/api/discord/callback', async (req, res) => {
    try {
        const { code, state, error } = req.query;

        if (error) {
            return res.status(400).send('Autorização Discord cancelada ou recusada.');
        }

        if (!code || !state || state !== req.session.discordState) {
            return res.status(400).send('Pedido Discord inválido.');
        }

        const tokenBody = new URLSearchParams({
            client_id: DISCORD_CLIENT_ID,
            client_secret: DISCORD_CLIENT_SECRET,
            grant_type: 'authorization_code',
            code: code,
            redirect_uri: DISCORD_REDIRECT_URI
        });

        const tokenResponse = await fetch(
            'https://discord.com/api/oauth2/token',
            {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: tokenBody
            }
        );

        const tokenData = await tokenResponse.json();

        if (!tokenResponse.ok || !tokenData.access_token) {
            console.error(tokenData);
            return res.status(400).send('Não foi possível obter o token Discord.');
        }

        const headers = {
            Authorization: 'Bearer ' + tokenData.access_token
        };

        // Perfil do utilizador
        const userResponse = await fetch(
            'https://discord.com/api/users/@me',
            { headers }
        );

        const user = await userResponse.json();

        // Membro no servidor (para obter roles)
        const memberResponse = await fetch(
            'https://discord.com/api/users/@me/guilds/' +
            DISCORD_GUILD_ID +
            '/member',
            { headers }
        );

        if (!memberResponse.ok) {
            return res.status(403).send(
                'Não tens acesso. Primeiro entra no servidor Discord oficial.'
            );
        }

        const member = await memberResponse.json();
        const hasRequiredRole = member.roles.includes(DISCORD_REQUIRED_ROLE_ID);

        if (!hasRequiredRole) {
            return res.status(403).send(
                'Não tens a role necessária no servidor Discord.'
            );
        }

        // Regista o login pendente com o ID gerado pela app.
        const requestId = req.session.discordRequestId;

        if (!requestId) {
            return res.status(400).send(
                'Pedido de login expirado ou inválido. Volta à aplicação e tenta novamente.'
            );
        }

        pendingDiscordLogins.set(requestId, {
            discordId: user.id,
            username: user.username,
            expiresAt: Date.now() + (5 * 60 * 1000)
        });

        return res.send(`
  <html>
    <body style="font-family: Arial; background: #111827; color: white; text-align: center; padding-top: 80px;">
      <h1>Discord validado com sucesso</h1>
      <p>Podes fechar esta página e voltar à aplicação JonyOptimizer.</p>
      <p>Utilizador: ${user.username}</p>
    </body>
  </html>
`);
    } catch (error) {
        console.error('Erro Discord OAuth:', error);

        return res.status(500).send(
            'Erro ao validar o Discord.'
        );
    }
});


// Criar uma licença manualmente.
// Mais tarde este endpoint deve ser protegido por autenticação de administrador.
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

        console.log(`✅ Licença criada: ${licenseKey}`);

        return res.json({
            success: true,
            license_key: licenseKey,
            discord_id,
            expires_at,
            max_devices: Number(max_devices) || 1
        });
    } catch (error) {
        console.error('❌ Erro ao criar licença:', error);

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

        // Obtém as licenças que podem ser usadas.
        const licenses = db.prepare(`
      SELECT *
      FROM licenses
      WHERE status = 'active'
        AND expires_at > CURRENT_TIMESTAMP
    `).all();

        // A chave está guardada como bcrypt hash.
        // Por isso é necessário compará-la com bcrypt.compareSync.
        let license = null;

        for (const currentLicense of licenses) {
            if (bcrypt.compareSync(license_key, currentLicense.license_key_hash)) {
                license = currentLicense;
                break;
            }
        }

        if (!license) {
            console.log('❌ Tentativa com chave inválida.');

            return res.status(404).json({
                valid: false,
                reason: 'license_not_found'
            });
        }

        // Verifica se este PC já está associado à licença.
        let device = db.prepare(`
      SELECT *
      FROM devices
      WHERE license_id = ?
        AND device_fingerprint = ?
        AND status = 'active'
    `).get(license.id, hwid);

        // Se é um computador novo, confirma o limite de dispositivos.
        if (!device) {
            const activeDevices = db.prepare(`
        SELECT COUNT(*) AS count
        FROM devices
        WHERE license_id = ?
          AND status = 'active'
      `).get(license.id);

            if (activeDevices.count >= license.max_devices) {
                console.log(`❌ Limite de dispositivos atingido: ${license.id}`);

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

        // Cria uma sessão válida durante sete dias.
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

        console.log(`✅ Licença ativada: ${license.id}`);

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
        console.error('❌ Erro de ativação:', error);

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

        const session = db.prepare(`
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

        if (!session) {
            return res.json({
                valid: false,
                reason: 'invalid_session',
                requires_reactivation: true
            });
        }

        if (
            session.license_status !== 'active' ||
            new Date(session.license_expires_at) <= new Date()
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
    `).run(session.device_id);

        return res.json({
            valid: true,
            license: {
                product: 'optimizer_pro',
                status: 'active'
            }
        });
    } catch (error) {
        console.error('❌ Erro de validação:', error);

        return res.status(500).json({
            valid: false,
            reason: 'server_error'
        });
    }
});
app.get('/api/discord/status/:requestId', (req, res) => {
    const login = pendingDiscordLogins.get(req.params.requestId);

    if (!login) {
        return res.json({
            success: false,
            status: 'pending'
        });
    }

    if (Date.now() > login.expiresAt) {
        pendingDiscordLogins.delete(req.params.requestId);

        return res.json({
            success: false,
            status: 'expired'
        });
    }

    return res.json({
        success: true,
        status: 'authorized',
        discordId: login.discordId,
        username: login.username
    });
});
app.listen(PORT, () => {
    console.log(`🚀 API a correr em http://localhost:${PORT}`);
    console.log('📊 Endpoints disponíveis:');
    console.log('   GET  /');
    console.log('   GET  /api/discord/callback');
    console.log('   GET  /api/discord/login/:requestId');
    console.log('   GET  /api/discord/status/:requestId');
    console.log('   POST /api/licenses/create');
    console.log('   POST /api/activate');
    console.log('   POST /api/validate');
});
