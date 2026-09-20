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
const nodemailer = require('nodemailer');

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

// Configuration Nodemailer
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

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

const User = mongoose.model('User', userSchema);
const ResetCode = mongoose.model('ResetCode', resetCodeSchema);

const authenticate = (req, res, next) => {
    const token = getCookie(req, 'ca_token') || req.headers.authorization?.replace(/^Bearer\s+/i, '');

    if (!token) {
        return res.status(401).json({ success: false, message: 'Non authentifié.' });
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
            return res.status(400).json({ success: false, message: 'Imèl sa a deja anrejistre deja!' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = await User.create({ name, email, password: hashedPassword });

        const token = jwt.sign({ id: newUser.id, email: newUser.email }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
        setAuthCookie(res, token);

        res.status(201).json({
            success: true,
            message: 'Kont ou an kreye avèk siksè!',
            user: { id: newUser.id, name: newUser.name, email: newUser.email }
        });
    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ success: false, message: 'Gen yon erè sou sèvè a.' });
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
            return res.status(400).json({ success: false, message: 'Imèl sa a oswa modpas la pa kòrèk.' });
        }

        if (!user.password) {
            return res.status(400).json({
                success: false,
                message: "Kont sa a te kreye ak Google. Tanpri klike sou 'Se connecter avec Google'."
            });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ success: false, message: 'Imèl sa a oswa modpas la pa kòrèk.' });
        }

        const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
        setAuthCookie(res, token);

        res.json({
            success: true,
            message: 'Ou konekte avèk siksè!',
            user: { id: user.id, name: user.name, email: user.email }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ success: false, message: 'Gen yon erè sou sèvè a.' });
    }
});

// 3. ROUTE POU GOOGLE LOGIN / SIGNUP OTOMATIK
app.post('/api/google-login', authLimiter, async (req, res) => {
    try {
        const { token } = req.body;

        if (!token) {
            return res.status(400).json({ success: false, message: 'Token Google manke.' });
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
            return res.status(400).json({ success: false, message: 'Token Google la pa valab.' });
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
            message: 'Koneksyon Google reyekti avèk siksè!',
            user: { id: user.id, name: user.name, email: user.email }
        });

    } catch (error) {
        console.error(error);
        res.status(400).json({ success: false, message: 'Token Google la pa valab.' });
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

        const mailOptions = {
            from: `"Competence Academy" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Code de réinitialisation de votre mot de passe - Competence Academy',
            html: `
                <div style="font-family: Arial, sans-serif; padding: 20px; color: #333; max-width: 500px; margin: 0 auto; border: 1px solid #e0e0e0; border-radius: 8px;">
                    <h2 style="color: #0056b3; text-align: center;">Competence Academy</h2>
                    <p>Bonjour,</p>
                    <p>Voici votre code de vérification pour réinitialiser votre mot de passe :</p>
                    <div style="text-align: center; margin: 25px 0;">
                        <span style="font-size: 32px; font-weight: bold; letter-spacing: 5px; color: #0056b3; background: #f0f4f8; padding: 10px 20px; border-radius: 6px;">${resetCode}</span>
                    </div>
                    <p style="font-size: 0.9em; color: #666;">Entrez ce code sur le site pour choisir votre nouveau mot de passe.</p>
                    <hr style="border: none; border-top: 1px solid #eee; margin-top: 20px;">
                    <p style="font-size: 0.8em; color: #999; text-align: center;">Competence Academy — Formation Pratique & Professionnelle</p>
                </div>
            `
        };

        await transporter.sendMail(mailOptions);
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

        res.json({ success: true, message: 'Votre mot de passe a été modifié avec succès !' });

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

// Gestion des utilisateurs en ligne (Socket.io)
let onlineUsers = 0;

io.on('connection', (socket) => {
    onlineUsers++;
    io.emit('updateOnlineCount', onlineUsers);

    socket.on('disconnect', () => {
        onlineUsers--;
        io.emit('updateOnlineCount', onlineUsers);
    });
});

// Démarrage du serveur après connexion à MongoDB
const startServer = async () => {
    const requiredEnvironment = {
        JWT_SECRET,
        MONGODB_URI,
        GOOGLE_CLIENT_ID,
        EMAIL_USER: process.env.EMAIL_USER,
        EMAIL_PASS: process.env.EMAIL_PASS,
        FRONTEND_URLS: FRONTEND_URLS.join(',')
    };
    const missingEnvironment = Object.keys(requiredEnvironment).filter((key) => !requiredEnvironment[key]);
    if (missingEnvironment.length > 0) {
        throw new Error(`Missing environment variables: ${missingEnvironment.join(', ')}`);
    }

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
