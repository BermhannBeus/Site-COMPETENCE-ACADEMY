if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config();
}

const express = require('express');
const http = require('http');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const mongoose = require('mongoose');
const { Server } = require('socket.io');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');
const webpush = require('web-push');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: true,
        methods: ["GET", "POST"],
        credentials: true
    }
});

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = '1h';
const MONGODB_URI = process.env.MONGODB_URI;
const VAPID_PUBLIC_KEY = process.env.VAPID_PUBLIC_KEY;
const VAPID_PRIVATE_KEY = process.env.VAPID_PRIVATE_KEY;
const PUSH_ADMIN_SECRET = process.env.PUSH_ADMIN_SECRET;
const FRONTEND_URLS = String(process.env.FRONTEND_URLS || process.env.FRONTEND_URL || '')
    .split(',')
    .map((url) => url.trim().replace(/\/$/, ''))
    .filter(Boolean);

// Client ID Google
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const client = new OAuth2Client(GOOGLE_CLIENT_ID);

const sanitizeEmail = (value = '') => String(value).trim().toLowerCase();
const isStrongPassword = (password = '') => {
    if (typeof password !== 'string') return false;
    return password.length >= 8 && /[A-Za-z]/.test(password) && /\d/.test(password);
};

const escapeHtml = (value = '') => String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
const createResetCode = () => crypto.randomInt(100000, 1000000).toString();
const hashResetCode = (code) => crypto.createHash('sha256').update(code).digest('hex');
const getCookie = (req, name) => {
    const cookies = String(req.headers.cookie || '').split(';');
    const cookie = cookies.find((item) => item.trim().startsWith(`${name}=`));
    return cookie ? decodeURIComponent(cookie.trim().slice(name.length + 1)) : '';
};
const setAuthCookie = (res, token) => {
    const isProduction = process.env.NODE_ENV === 'production';
    const attributes = [
        'HttpOnly',
        'Path=/',
        'Max-Age=3600',
        isProduction ? 'Secure' : '',
        isProduction ? 'SameSite=None' : 'SameSite=Lax'
    ].filter(Boolean).join('; ');
    res.setHeader('Set-Cookie', `ca_token=${encodeURIComponent(token)}; ${attributes}`);
};
const clearAuthCookie = (res) => {
    res.setHeader('Set-Cookie', 'ca_token=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax');
};

const sendResetEmail = async (to, resetCode) => {
    const response = await fetch('https://api.brevo.com/v3/smtp/email', {
        method: 'POST',
        headers: {
            'api-key': process.env.BREVO_API_KEY,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            sender: {
                name: 'Competence Academy',
                email: process.env.BREVO_SENDER_EMAIL
            },
            to: [{ email: to }],
            subject: 'Code de réinitialisation de votre mot de passe - Competence Academy',
            htmlContent: `
                <div style="font-family: Arial, sans-serif; padding: 20px; color: #333; max-width: 500px; margin: 0 auto; border: 1px solid #e0e0e0; border-radius: 8px;">
                    <h2 style="color: #0056b3; text-align: center;">Competence Academy</h2>
                    <p>Bonjour,</p>
                    <p>Voici votre code de vérification pour réinitialiser votre mot de passe :</p>
                    <div style="text-align: center; margin: 25px 0;">
                        <span style="font-size: 32px; font-weight: bold; letter-spacing: 5px; color: #0056b3; background: #f0f4f8; padding: 10px 20px; border-radius: 6px;">${resetCode}</span>
                    </div>
                    <p style="font-size: 0.9em; color: #666;">Ce code expire dans 10 minutes.</p>
                </div>
            `
        })
    });

    if (!response.ok) {
        const details = await response.text();
        throw new Error(`Brevo API ${response.status}: ${details}`);
    }
};

const allowedOrigins = [
    'http://localhost',
    'http://localhost:5000',
    'http://127.0.0.1',
    'http://127.0.0.1:5000',
    ...FRONTEND_URLS
];

// Middleware
app.use(express.json({ limit: '1mb' }));
app.use(cors({
    origin: (origin, callback) => {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
            return;
        }
        callback(new Error('Not allowed by CORS'));
    },
    credentials: true
}));
app.use('/api/', rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, message: 'Trop de requêtes, veuillez réessayer plus tard.' }
}));
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    skipSuccessfulRequests: true,
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, message: 'Trop de tentatives. Veuillez réessayer dans quelques minutes.' }
});
const resetLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, message: 'Trop de demandes de récupération. Veuillez réessayer plus tard.' }
});
const contactLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, message: 'Trop de messages envoyés. Veuillez réessayer plus tard.' }
});

app.post('/api/contact', contactLimiter, async (req, res) => {
    try {
        const name = String(req.body?.name || '').trim();
        const email = sanitizeEmail(req.body?.email);
        const message = String(req.body?.message || '').trim();

        if (!name || name.length > 100 || !email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            return res.status(400).json({ success: false, message: 'Veuillez vérifier votre nom et votre adresse e-mail.' });
        }
        if (!message || message.length > 5000) {
            return res.status(400).json({ success: false, message: 'Veuillez saisir un message valide.' });
        }

        const response = await fetch('https://api.brevo.com/v3/smtp/email', {
            method: 'POST',
            headers: {
                'api-key': process.env.BREVO_API_KEY,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                sender: {
                    name: 'Commentaire du site',
                    email: process.env.BREVO_SENDER_EMAIL
                },
                to: [{ email: 'competenceacademy34@gmail.com', name: 'Competence Academy' }],
                replyTo: { email, name },
                subject: `Commentaire du site - ${name}`,
                htmlContent: `
                    <div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;color:#17213d">
                        <h2 style="color:#111e62">Commentaire du site</h2>
                        <p><strong>Nom :</strong> ${escapeHtml(name)}</p>
                        <p><strong>E-mail :</strong> ${escapeHtml(email)}</p>
                        <p><strong>Message :</strong></p>
                        <div style="padding:16px;background:#f5f7fb;border-left:4px solid #f76b00;white-space:pre-wrap">${escapeHtml(message)}</div>
                    </div>
                `
            })
        });

        if (!response.ok) {
            const details = await response.text();
            throw new Error(`Brevo contact API ${response.status}: ${details}`);
        }
        res.json({ success: true, message: 'Votre message a été envoyé avec succès.' });
    } catch (error) {
        console.error('Contact form error:', error);
        res.status(500).json({ success: false, message: 'Impossible d’envoyer votre message pour le moment.' });
    }
});

const userSchema = new mongoose.Schema({
    name: { type: String, required: true, trim: true, maxlength: 100 },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true, index: true },
    password: { type: String, default: '' },
    googleId: { type: String, default: '' }
}, { timestamps: true });

const resetCodeSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true, index: true },
    codeHash: { type: String, required: true },
    expiresAt: { type: Date, required: true, index: { expires: 0 } }
});

const pushSubscriptionSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
    endpoint: { type: String, required: true, unique: true },
    subscription: { type: Object, required: true }
}, { timestamps: true });

const User = mongoose.model('User', userSchema);
const ResetCode = mongoose.model('ResetCode', resetCodeSchema);
const PushSubscription = mongoose.model('PushSubscription', pushSubscriptionSchema);

const authenticate = (req, res, next) => {
    const token = getCookie(req, 'ca_token') || req.headers.authorization?.replace(/^Bearer\s+/i, '');

    if (!token) {
        return res.status(401).json({ success: false, message: 'Vous devez être connecté.' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(401).json({ success: false, message: 'Session expirée ou invalide.' });
    }
};

// 1. ROUTE POU SIGNUP (Enskripsyon)
app.post('/api/signup', authLimiter, async (req, res) => {
    try {
        const name = String(req.body?.name || '').trim();
        const email = sanitizeEmail(req.body?.email);
        const password = String(req.body?.password || '');

        if (!name || !email || !password) {
            return res.status(400).json({ success: false, message: 'Veuillez remplir tous les champs.' });
        }

        if (!/^\S+@\S+\.\S+$/.test(email)) {
            return res.status(400).json({ success: false, message: 'Adresse e-mail invalide.' });
        }

        if (!isStrongPassword(password)) {
            return res.status(400).json({ success: false, message: 'Le mot de passe doit contenir au moins 8 caractères avec lettres et chiffres.' });
        }

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ success: false, message: 'Cette adresse e-mail est déjà enregistrée.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = await User.create({ name, email, password: hashedPassword });

        const token = jwt.sign({ id: newUser.id, email: newUser.email }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
        setAuthCookie(res, token);

        res.status(201).json({
            success: true,
            message: 'Votre compte a été créé avec succès !',
            user: { id: newUser.id, name: newUser.name, email: newUser.email }
        });
    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ success: false, message: 'Une erreur est survenue sur le serveur.' });
    }
});

// 2. ROUTE POU LOGIN (Koneksyon)
app.post('/api/login', authLimiter, async (req, res) => {
    try {
        const email = sanitizeEmail(req.body?.email);
        const password = String(req.body?.password || '');

        if (!email || !password) {
            return res.status(400).json({ success: false, message: 'Veuillez fournir un email et un mot de passe.' });
        }

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ success: false, message: 'L’adresse e-mail ou le mot de passe est incorrect.' });
        }

        if (!user.password) {
            return res.status(400).json({
                success: false,
                message: "Ce compte a été créé avec Google. Cliquez sur « Se connecter avec Google »."
            });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ success: false, message: 'L’adresse e-mail ou le mot de passe est incorrect.' });
        }

        const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
        setAuthCookie(res, token);

        res.json({
            success: true,
            message: 'Connexion réussie !',
            user: { id: user.id, name: user.name, email: user.email }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ success: false, message: 'Une erreur est survenue sur le serveur.' });
    }
});

// 3. ROUTE POU GOOGLE LOGIN / SIGNUP OTOMATIK
app.post('/api/google-login', authLimiter, async (req, res) => {
    try {
        const { token } = req.body;

        if (!token) {
            return res.status(400).json({ success: false, message: 'Le jeton Google est manquant.' });
        }

        const ticket = await client.verifyIdToken({
            idToken: token,
            audience: GOOGLE_CLIENT_ID
        });

        const payload = ticket.getPayload();
        const email = sanitizeEmail(payload?.email);
        const name = String(payload?.name || 'Utilisateur').trim();
        const googleId = payload?.sub;

        if (!email || !googleId) {
            return res.status(400).json({ success: false, message: 'Le jeton Google est invalide.' });
        }

        let user = await User.findOne({ email });

        if (!user) {
            user = await User.create({ name, email, googleId });
        } else if (!user.googleId) {
            user.googleId = googleId;
            await user.save();
        }

        const appToken = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
        setAuthCookie(res, appToken);

        res.json({
            success: true,
            message: 'Connexion Google réussie !',
            user: { id: user.id, name: user.name, email: user.email }
        });

    } catch (error) {
        console.error(error);
        res.status(400).json({ success: false, message: 'Le jeton Google est invalide.' });
    }
});

// 4. ROUTE POU MANDE KÒD REKIPERASYON (ENVOI DU CODE À 6 CHIFFRES)
app.post('/api/forgot-password', resetLimiter, async (req, res) => {
    const email = sanitizeEmail(req.body?.email);

    if (!email || !/^\S+@\S+\.\S+$/.test(email)) {
        return res.status(400).json({ success: false, message: 'Veuillez fournir un email valide.' });
    }

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.json({ success: true, message: 'Si votre adresse existe, un code de vérification a été envoyé.' });
        }

        const resetCode = createResetCode();
        await ResetCode.findOneAndUpdate(
            { email },
            {
                email,
                codeHash: hashResetCode(resetCode),
                expiresAt: new Date(Date.now() + 10 * 60 * 1000)
            },
            { upsert: true, new: true }
        );

        await sendResetEmail(email, resetCode);
        return res.json({ success: true, message: 'Un code à 6 chiffres a été envoyé sur votre email !' });

    } catch (error) {
        console.error("Erreur d'envoi d'email:", error);
        return res.status(500).json({ success: false, message: "Erreur lors de l'envoi de l'email." });
    }
});

// 5. ROUTE POU VERIFYE KÒD LA AK CHANJE MODPAS LA
app.post('/api/reset-password-code', resetLimiter, async (req, res) => {
    try {
        const email = sanitizeEmail(req.body?.email);
        const code = String(req.body?.code || '');
        const newPassword = String(req.body?.newPassword || '');

        if (!email || !code || !newPassword) {
            return res.status(400).json({ success: false, message: 'Veuillez remplir tous les champs.' });
        }

        if (!isStrongPassword(newPassword)) {
            return res.status(400).json({ success: false, message: 'Le nouveau mot de passe doit contenir au moins 8 caractères avec lettres et chiffres.' });
        }

        const resetEntry = await ResetCode.findOne({ email });
        if (!resetEntry || resetEntry.expiresAt <= new Date() || resetEntry.codeHash !== hashResetCode(code)) {
            return res.status(400).json({ success: false, message: 'Le code est incorrect ou a expiré !' });
        }

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ success: false, message: 'Cet utilisateur n\'existe pas.' });
        }

        user.password = await bcrypt.hash(newPassword, 10);

        await ResetCode.deleteOne({ email });
        const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
        setAuthCookie(res, token);

        res.json({
            success: true,
            message: 'Votre mot de passe a été modifié avec succès !',
            user: { id: user.id, name: user.name, email: user.email }
        });

    } catch (error) {
        console.error('Reset password error:', error);
        res.status(500).json({ success: false, message: 'Erreur sur le serveur.' });
    }
});

app.get('/api/me', authenticate, async (req, res) => {
    try {
        const user = await User.findOne({ _id: req.user.id, email: req.user.email });
        if (!user) {
            return res.status(404).json({ success: false, message: 'Utilisateur introuvable.' });
        }

        res.json({
            success: true,
            user: { id: user.id, name: user.name, email: user.email }
        });
    } catch (error) {
        console.error('Get current user error:', error);
        res.status(500).json({ success: false, message: 'Erreur sur le serveur.' });
    }
});

app.post('/api/logout', (req, res) => {
    clearAuthCookie(res);
    res.json({ success: true, message: 'Déconnexion réussie.' });
});

app.get('/api/push/public-key', (req, res) => {
    res.json({ success: true, publicKey: VAPID_PUBLIC_KEY });
});

app.post('/api/push/subscribe', async (req, res) => {
    try {
        const subscription = req.body?.subscription;
        if (!subscription?.endpoint || !subscription?.keys?.p256dh || !subscription?.keys?.auth) {
            return res.status(400).json({ success: false, message: 'Abonnement de notification invalide.' });
        }

        let userId;
        const token = getCookie(req, 'ca_token');
        if (token) {
            try {
                userId = jwt.verify(token, JWT_SECRET).id;
            } catch (error) {
                userId = undefined;
            }
        }

        await PushSubscription.findOneAndUpdate(
            { endpoint: subscription.endpoint },
            { userId, endpoint: subscription.endpoint, subscription },
            { upsert: true, new: true, setDefaultsOnInsert: true }
        );
        res.json({ success: true, message: 'Notifications activées avec succès.' });
    } catch (error) {
        console.error('Push subscription error:', error);
        res.status(500).json({ success: false, message: 'Impossible d’activer les notifications.' });
    }
});

app.delete('/api/push/subscribe', async (req, res) => {
    try {
        const endpoint = String(req.body?.endpoint || '');
        if (!endpoint) return res.status(400).json({ success: false, message: 'Abonnement introuvable.' });
        await PushSubscription.deleteOne({ endpoint });
        res.json({ success: true });
    } catch (error) {
        console.error('Push unsubscribe error:', error);
        res.status(500).json({ success: false, message: 'Impossible de désactiver les notifications.' });
    }
});

app.post('/api/push/notify', async (req, res) => {
    if (!PUSH_ADMIN_SECRET || req.headers['x-push-admin-secret'] !== PUSH_ADMIN_SECRET) {
        return res.status(401).json({ success: false, message: 'Accès non autorisé.' });
    }

    const title = String(req.body?.title || 'Competence Academy').slice(0, 100);
    const body = String(req.body?.body || 'Une nouvelle mise à jour est disponible.').slice(0, 300);
    const subscriptions = await PushSubscription.find().lean();
    const results = await Promise.allSettled(subscriptions.map(async (item) => {
        try {
            await webpush.sendNotification(item.subscription, JSON.stringify({ title, body, url: '/' }));
        } catch (error) {
            if (error.statusCode === 404 || error.statusCode === 410) {
                await PushSubscription.deleteOne({ _id: item._id });
            }
            throw error;
        }
    }));

    res.json({
        success: true,
        sent: results.filter((result) => result.status === 'fulfilled').length,
        removed: results.filter((result) => result.status === 'rejected').length
    });
});

// Gestion des utilisateurs connectés (Socket.io)
const onlineUsers = new Map();

io.use((socket, next) => {
    const token = getCookie({ headers: socket.handshake.headers }, 'ca_token');
    if (!token) return next(new Error('Authentification requise.'));

    try {
        socket.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch (error) {
        next(new Error('Session expirée ou invalide.'));
    }
});

const broadcastOnlineUsers = () => {
    io.emit('onlineCount', onlineUsers.size);
};

io.on('connection', (socket) => {
    const userId = String(socket.user.id);
    const currentUser = onlineUsers.get(userId) || {
        id: userId,
        name: socket.user.email,
        sockets: new Set()
    };
    currentUser.sockets.add(socket.id);
    onlineUsers.set(userId, currentUser);
    socket.emit('onlineIdentity', { id: userId, name: currentUser.name });

    User.findById(userId).select('name email').lean()
        .then((user) => {
            if (!user || !onlineUsers.has(userId)) return;
            const connectedUser = onlineUsers.get(userId);
            connectedUser.name = user.name || user.email;
            socket.emit('onlineIdentity', { id: userId, name: connectedUser.name });
            broadcastOnlineUsers();
        })
        .catch((error) => {
            console.error('Online user lookup error:', error);
        });
    broadcastOnlineUsers();

    socket.on('disconnect', () => {
        const connectedUser = onlineUsers.get(userId);
        if (connectedUser) {
            connectedUser.sockets.delete(socket.id);
            if (connectedUser.sockets.size === 0) onlineUsers.delete(userId);
        }
        broadcastOnlineUsers();
    });
});

// Démarrage du serveur après connexion à MongoDB
const startServer = async () => {
    const requiredEnvironment = {
        JWT_SECRET,
        MONGODB_URI,
        GOOGLE_CLIENT_ID,
        BREVO_API_KEY: process.env.BREVO_API_KEY,
        BREVO_SENDER_EMAIL: process.env.BREVO_SENDER_EMAIL,
        VAPID_PUBLIC_KEY,
        VAPID_PRIVATE_KEY,
        PUSH_ADMIN_SECRET,
        FRONTEND_URLS: FRONTEND_URLS.join(',')
    };
    const missingEnvironment = Object.keys(requiredEnvironment).filter((key) => !requiredEnvironment[key]);
    if (missingEnvironment.length > 0) {
        throw new Error(`Missing environment variables: ${missingEnvironment.join(', ')}`);
    }

    webpush.setVapidDetails(
        'mailto:competenceacademy34@gmail.com',
        VAPID_PUBLIC_KEY,
        VAPID_PRIVATE_KEY
    );

    await mongoose.connect(MONGODB_URI, {
        serverSelectionTimeoutMS: 10000
    });
    console.log('MongoDB connected');

    server.listen(PORT, () => {
        console.log(`Server Competence Academy Run ${PORT}`);
    });
};

startServer().catch((error) => {
    console.error('Server startup failed:', error.message);
    process.exit(1);
});
