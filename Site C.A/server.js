if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config();
}

const express = require('express');
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const cookieParser = require('cookie-parser');
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
app.set('trust proxy', 1);
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
const COURSE_VIDEO_DIR = path.resolve(process.env.COURSE_VIDEO_DIR || path.join(__dirname, 'private-videos'));
const FRONTEND_URLS = String(process.env.FRONTEND_URLS || process.env.FRONTEND_URL || '')
    .split(',')
    .map((url) => url.trim().replace(/\/$/, ''))
    .filter(Boolean);

io.use((socket, next) => {
    const cookieHeader = socket.handshake.headers.cookie || '';
    const authCookie = cookieHeader.split(';').map((cookie) => cookie.trim())
        .find((cookie) => cookie.startsWith('ca_token='));
    const token = authCookie ? authCookie.slice('ca_token='.length) : '';

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        if (!decoded.id || decoded.accessConfirmed !== true) {
            return next(new Error('Authentication required'));
        }
        socket.data.userId = String(decoded.id);
        next();
    } catch (error) {
        next(new Error('Authentication required'));
    }
});

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
const setAuthCookie = (res, token) => {
    const isProduction = process.env.NODE_ENV === 'production';
    res.cookie('ca_token', token, {
        httpOnly: true,
        secure: isProduction,
        sameSite: isProduction ? 'None' : 'Lax',
        maxAge: 60 * 60 * 1000,
        path: '/'
    });
};
const clearAuthCookie = (res) => {
    res.clearCookie('ca_token', { path: '/' });
};
const sendAuthenticatedSession = (res, user) => {
    const token = jwt.sign(
        { id: user.id, email: user.email, accessConfirmed: true },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRES_IN }
    );
    setAuthCookie(res, token);
    const serializedUser = {
        id: user.id,
        name: user.name,
        email: user.email,
        nameOnCertificate: user.nameOnCertificate,
        phone: user.phone,
        location: user.location,
        registeredCourse: user.registeredCourse
    };
    return res.json({
        success: true,
        authenticated: true,
        user: serializedUser,
        profileComplete: Boolean(
            user.nameOnCertificate && user.phone && user.location && user.registeredCourse
        )
    });
};

// Configuration Nodemailer
const transporter = nodemailer.createTransport({
    service: 'gmail',
    connectionTimeout: 10000,
    greetingTimeout: 10000,
    socketTimeout: 15000,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

const sendEmail = async (mailOptions) => {
    if (process.env.BREVO_API_KEY) {
        const senderEmail = process.env.BREVO_SENDER_EMAIL;
        if (!senderEmail) {
            const error = new Error('BREVO_SENDER_EMAIL must be configured when using Brevo.');
            error.code = 'EMAIL_DELIVERY_FAILED';
            throw error;
        }

        let response;
        try {
            response = await fetch('https://api.brevo.com/v3/smtp/email', {
                method: 'POST',
                headers: {
                    'api-key': process.env.BREVO_API_KEY,
                    'Content-Type': 'application/json',
                    accept: 'application/json'
                },
                body: JSON.stringify({
                    sender: {
                        email: senderEmail,
                        name: process.env.BREVO_SENDER_NAME || 'Competence Academy'
                    },
                    to: (Array.isArray(mailOptions.to) ? mailOptions.to : [mailOptions.to])
                        .map((recipient) => typeof recipient === 'string'
                            ? { email: recipient }
                            : recipient),
                    subject: mailOptions.subject,
                    ...(mailOptions.text ? { textContent: mailOptions.text } : {}),
                    ...(mailOptions.html ? { htmlContent: mailOptions.html } : {})
                }),
                signal: AbortSignal.timeout(15000)
            });
        } catch (cause) {
            const error = new Error('Brevo could not be reached to send the email.');
            error.code = 'EMAIL_DELIVERY_FAILED';
            error.cause = cause;
            throw error;
        }

        if (!response.ok) {
            const details = await response.text();
            const error = new Error(`Brevo rejected the email (${response.status}): ${details}`);
            error.code = 'EMAIL_DELIVERY_FAILED';
            throw error;
        }
        return response.json();
    }

    if (process.env.RESEND_API_KEY) {
        const from = process.env.EMAIL_FROM;
        if (!from) {
            const error = new Error('EMAIL_FROM must be configured when using Resend.');
            error.code = 'EMAIL_DELIVERY_FAILED';
            throw error;
        }

        let response;
        try {
            response = await fetch('https://api.resend.com/emails', {
                method: 'POST',
                headers: {
                    Authorization: `Bearer ${process.env.RESEND_API_KEY}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    from,
                    to: Array.isArray(mailOptions.to) ? mailOptions.to : [mailOptions.to],
                    subject: mailOptions.subject,
                    ...(mailOptions.text ? { text: mailOptions.text } : {}),
                    ...(mailOptions.html ? { html: mailOptions.html } : {})
                }),
                signal: AbortSignal.timeout(15000)
            });
        } catch (cause) {
            const error = new Error('The email provider could not be reached.');
            error.code = 'EMAIL_DELIVERY_FAILED';
            error.cause = cause;
            throw error;
        }

        if (!response.ok) {
            const details = await response.text();
            const error = new Error(`Email provider rejected the message (${response.status}): ${details}`);
            error.code = 'EMAIL_DELIVERY_FAILED';
            throw error;
        }
        return response.json();
    }

    try {
        return await transporter.sendMail({
            ...mailOptions,
            from: process.env.EMAIL_FROM || mailOptions.from || process.env.EMAIL_USER
        });
    } catch (cause) {
        const error = new Error('SMTP email delivery failed.');
        error.code = 'EMAIL_DELIVERY_FAILED';
        error.cause = cause;
        throw error;
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
app.use(cookieParser());
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
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, message: 'Trop de tentatives. Veuillez réessayer dans quelques minutes.' }
});
const resetRequestLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, message: 'Trop de demandes de récupération. Veuillez réessayer plus tard.' }
});
const resetVerificationLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, message: 'Trop de tentatives de vérification. Veuillez réessayer plus tard.' }
});
const accessCodeLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, message: 'Trop de tentatives de confirmation. Réessayez plus tard.' }
});

const COURSE_VIDEO_SEQUENCES = {
    bureautique: ['bureautique-word'],
    photographie: ['photographie-manuel'],
    design: ['design-logo'],
    videographie: ['videographie-cadrage'],
    montage: ['montage-rythmique'],
    quickbooks: ['quickbooks-introduction'],
    surveillance: ['surveillance-installation']
};
const COURSE_VIDEO_FILES = {
    'bureautique-word': 'bureautique-word.mp4',
    'photographie-manuel': 'photographie-manuel.mp4',
    'design-logo': 'design-logo.mp4',
    'videographie-cadrage': 'videographie-cadrage.mp4',
    'montage-rythmique': 'montage-rythmique.mp4',
    'quickbooks-introduction': 'quickbooks-introduction.mp4',
    'surveillance-installation': 'surveillance-installation.mp4'
};
const COURSE_TITLES = {
    bureautique: 'Informatique Bureautique',
    photographie: 'Photographie',
    design: 'Design Graphic',
    videographie: 'Vidéographie',
    montage: 'Montage Vidéo',
    quickbooks: 'QuickBooks',
    surveillance: 'Surveillance'
};
const COURSE_ACCESS_CATEGORIES = Object.keys(COURSE_TITLES);
const getCourseForVideo = (videoId) => COURSE_ACCESS_CATEGORIES.find(
    (courseId) => COURSE_VIDEO_SEQUENCES[courseId]?.includes(videoId)
);

const userSchema = new mongoose.Schema({
    name: { type: String, required: true, trim: true, maxlength: 100 },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true, index: true },
    password: { type: String, default: '' },
    googleId: { type: String, default: '' },
    nameOnCertificate: { type: String, default: '', trim: true, maxlength: 100 },
    phone: { type: String, default: '', trim: true, maxlength: 30 },
    location: { type: String, default: '', trim: true, maxlength: 100 },
    registeredCourse: { type: String, default: '', enum: ['', ...COURSE_ACCESS_CATEGORIES] },
    accessApprovedAt: { type: Date, default: null }
}, { timestamps: true });

const resetCodeSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true, index: true },
    codeHash: { type: String, required: true },
    expiresAt: { type: Date, required: true, index: { expires: 0 } }
});
const courseProgressSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true, index: true },
    unlockedVideoIds: { type: [String], default: [] },
    completedVideoIds: { type: [String], default: [] }
}, { timestamps: true });
const videoWatchSessionSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    videoId: { type: String, required: true },
    courseId: { type: String, required: true },
    furthestPosition: { type: Number, default: 0 },
    watchedSeconds: { type: Number, default: 0 },
    duration: { type: Number, default: 0 },
    lastPosition: { type: Number, default: 0 },
    lastReportedAt: { type: Date, default: Date.now },
    expiresAt: { type: Date, required: true, index: { expires: 0 } }
}, { timestamps: true });
const courseAccessCodeSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    courseId: { type: String, required: true },
    codeHash: { type: String, required: true, unique: true },
    grantedAt: { type: Date, required: true }
}, { timestamps: true });
courseAccessCodeSchema.index({ userId: 1, courseId: 1 }, { unique: true });
const accessConfirmationSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true, index: true },
    challengeId: { type: String, required: true, unique: true },
    codeHash: { type: String, required: true },
    attempts: { type: Number, default: 0 },
    expiresAt: { type: Date, required: true, index: { expires: 0 } }
}, { timestamps: true });

const User = mongoose.model('User', userSchema);
const ResetCode = mongoose.model('ResetCode', resetCodeSchema);
const CourseProgress = mongoose.model('CourseProgress', courseProgressSchema);
const VideoWatchSession = mongoose.model('VideoWatchSession', videoWatchSessionSchema);
const CourseEnrollmentAccess = mongoose.model('CourseEnrollmentAccess', courseAccessCodeSchema);
const AccessConfirmation = mongoose.model('AccessConfirmation', accessConfirmationSchema);

const getStudentAccessOtp = (user) => {
    const digest = crypto.createHmac('sha256', JWT_SECRET)
        .update(`course-page-access:${user.id}:${user.email}`)
        .digest();
    return String(digest.readUInt32BE(0) % 1000000).padStart(6, '0');
};

const grantCourseAccess = async (user, courseId) => {
    const existingAccess = await CourseEnrollmentAccess.findOne({ userId: user._id, courseId });
    if (existingAccess) return false;

    const code = crypto.randomBytes(24).toString('base64url');
    const grantedAt = new Date();
    await CourseEnrollmentAccess.create({ userId: user._id, courseId, codeHash: hashResetCode(code), grantedAt });
    try {
        await sendEmail({
            to: user.email,
            subject: `Votre code d’accès - ${COURSE_TITLES[courseId]} | Competence Academy`,
            text: `Bonjour ${user.name},\n\nVotre paiement ayant été confirmé, voici votre code personnel pour la formation « ${COURSE_TITLES[courseId]} » :\n\n${code}\n\nCe code est réservé à votre compte et à cette formation. Il reste valable tant que votre accès à la formation est actif. Ne le partagez pas.\n\nCompetence Academy`
        });
    } catch (error) {
        await CourseEnrollmentAccess.deleteOne({ userId: user._id, courseId });
        throw error;
    }
    return true;
};

const createAccessConfirmation = async (user) => {
    const approvalEmail = sanitizeEmail(process.env.ACCESS_APPROVAL_EMAIL || process.env.EMAIL_USER);
    if (!/^\S+@\S+\.\S+$/.test(approvalEmail)) {
        throw new Error('ACCESS_APPROVAL_EMAIL or EMAIL_USER must be configured with a valid email address.');
    }

    const code = getStudentAccessOtp(user);
    const challengeId = crypto.randomBytes(24).toString('hex');
    const expiresAt = new Date(Date.now() + 20 * 60 * 1000);
    await AccessConfirmation.findOneAndUpdate(
        { userId: user._id },
        { challengeId, codeHash: hashResetCode(code), attempts: 0, expiresAt },
        { upsert: true, new: true, setDefaultsOnInsert: true }
    );
    try {
        await sendEmail({
            to: approvalEmail,
            subject: 'Demande de confirmation de connexion - Competence Academy',
            text: `Nouvelle demande de connexion à l’espace de cours.\n\nNom : ${user.name}\nE-mail : ${user.email}\nCode personnel de cet étudiant : ${code}\n\nCe code reste le même pour cette adresse e-mail tant que JWT_SECRET ne change pas. Cette demande expire dans 20 minutes. Après une première confirmation réussie, aucune nouvelle confirmation ne sera demandée pour ce compte.`
        });
    } catch (error) {
        await AccessConfirmation.deleteOne({ userId: user._id, challengeId });
        throw error;
    }

    return {
        challengeId,
        message: 'Demande envoyée à l’administration. Saisissez le code de confirmation qui vous sera communiqué dans les 20 minutes.'
    };
};

const isValidCourseAccessCode = async (userId, courseId, code) => {
    if (!code || code.length > 128) return false;
    const entry = await CourseEnrollmentAccess.findOne({ userId, courseId });
    if (!entry) return false;

    const submittedHash = Buffer.from(hashResetCode(code), 'hex');
    const expectedHash = Buffer.from(entry.codeHash, 'hex');
    return submittedHash.length === expectedHash.length && crypto.timingSafeEqual(submittedHash, expectedHash);
};

const serializeCourseProgress = (progress) => ({
    unlockedVideoIds: progress.unlockedVideoIds,
    completedVideoIds: progress.completedVideoIds
});

const getOrCreateCourseProgress = async (userId) => {
    let progress = await CourseProgress.findOne({ userId });
    if (progress) return progress;

    try {
        progress = await CourseProgress.create({ userId });
    } catch (error) {
        if (error.code !== 11000) throw error;
        progress = await CourseProgress.findOne({ userId });
        if (!progress) throw error;
    }
    return progress;
};

const recordVideoWatchProgress = async ({ userId, videoId, watchSessionId, currentTime, duration }) => {
    if (!mongoose.isValidObjectId(watchSessionId)
        || !Number.isFinite(currentTime)
        || !Number.isFinite(duration)
        || currentTime < 0
        || duration <= 0
        || duration > 8 * 60 * 60) {
        return { error: 'Progression vidéo invalide.' };
    }

    const watchSession = await VideoWatchSession.findOne({
        _id: watchSessionId,
        userId,
        videoId,
        expiresAt: { $gt: new Date() }
    });
    if (!watchSession) return { error: 'Session vidéo expirée. Relancez la vidéo.' };

    if (currentTime > duration + 1
        || (watchSession.duration > 0
            && Math.abs(watchSession.duration - duration) > Math.max(3, duration * 0.02))) {
        return { error: 'Durée de la vidéo incohérente.' };
    }

    const now = new Date();
    const elapsedSeconds = Math.max(0, (now.getTime() - watchSession.lastReportedAt.getTime()) / 1000);
    const safePosition = Math.min(currentTime, duration);
    const forwardSeconds = safePosition - watchSession.lastPosition;
    if (forwardSeconds > elapsedSeconds * 1.75 + 2) {
        return { error: 'La vidéo a été avancée trop rapidement. Reprenez la lecture à partir de votre progression.' };
    }

    if (watchSession.duration === 0) watchSession.duration = duration;
    if (forwardSeconds > 0) {
        watchSession.watchedSeconds = Math.min(
            duration,
            watchSession.watchedSeconds + Math.min(forwardSeconds, elapsedSeconds + 1)
        );
    }
    watchSession.furthestPosition = Math.max(watchSession.furthestPosition, safePosition);
    watchSession.lastPosition = safePosition;
    watchSession.lastReportedAt = now;
    await watchSession.save();
    return { watchSession };
};

const authenticate = (req, res, next) => {
    const token = req.cookies?.ca_token || req.headers.authorization?.replace(/^Bearer\s+/i, '');

    if (!token) {
        return res.status(401).json({ success: false, message: 'Non authentifié.' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        if (decoded.accessConfirmed !== true) {
            return res.status(401).json({ success: false, message: 'Confirmation de connexion requise.' });
        }
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(401).json({ success: false, message: 'Session expirée ou invalide.' });
    }
};

const requireCourseAdmin = (req, res, next) => {
    const configuredKey = process.env.COURSE_ADMIN_API_KEY;
    if (!configuredKey) {
        return res.status(503).json({ success: false, message: 'L’administration des accès aux cours n’est pas configurée.' });
    }

    const submittedKey = String(req.get('x-course-admin-key') || '');
    const submittedBuffer = Buffer.from(submittedKey);
    const expectedBuffer = Buffer.from(configuredKey);
    if (submittedBuffer.length !== expectedBuffer.length || !crypto.timingSafeEqual(submittedBuffer, expectedBuffer)) {
        return res.status(401).json({ success: false, message: 'Accès administrateur refusé.' });
    }
    next();
};

// 1. Route d’inscription
app.post('/api/signup', authLimiter, async (req, res) => {
    try {
        const name = String(req.body?.name || '').trim();
        const email = sanitizeEmail(req.body?.email);
        const password = String(req.body?.password || '');
        const phone = String(req.body?.phone || '').trim();
        const location = String(req.body?.location || '').trim();
        const registeredCourse = String(req.body?.registeredCourse || '');

        if (!name || !email || !password || !phone || !location || !registeredCourse) {
            return res.status(400).json({ success: false, message: 'Veuillez remplir tous les champs.' });
        }

        if (!/^\S+@\S+\.\S+$/.test(email)) {
            return res.status(400).json({ success: false, message: 'Adresse e-mail invalide.' });
        }

        if (name.length > 100 || phone.length > 30 || !/^[+0-9().\-\s]{7,30}$/.test(phone) || location.length > 100 || location.length < 2) {
            return res.status(400).json({ success: false, message: 'Vérifiez le nom, le téléphone et la ville/pays saisis.' });
        }
        if (!COURSE_ACCESS_CATEGORIES.includes(registeredCourse)) {
            return res.status(400).json({ success: false, message: 'Veuillez choisir une formation valide.' });
        }

        if (!isStrongPassword(password)) {
            return res.status(400).json({ success: false, message: 'Le mot de passe doit contenir au moins 8 caractères avec lettres et chiffres.' });
        }

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ success: false, message: 'Cette adresse e-mail est déjà utilisée.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = await User.create({
            name,
            nameOnCertificate: name,
            email,
            password: hashedPassword,
            phone,
            location,
            registeredCourse
        });
        const confirmation = await createAccessConfirmation(newUser);

        res.status(201).json({
            success: true,
            ...confirmation
        });
    } catch (error) {
        console.error('Signup error:', error);
        if (error.code === 'EMAIL_DELIVERY_FAILED') {
            return res.status(503).json({
                success: false,
                message: 'Votre compte est enregistré, mais l’e-mail de confirmation ne peut pas être envoyé pour le moment. Veuillez réessayer plus tard.'
            });
        }
        res.status(500).json({ success: false, message: 'Une erreur est survenue sur le serveur.' });
    }
});

// 2. Route de connexion
app.post('/api/login', authLimiter, async (req, res) => {
    try {
        const email = sanitizeEmail(req.body?.email);
        const password = String(req.body?.password || '');

        if (!email || !password) {
            return res.status(400).json({ success: false, message: 'Veuillez fournir un email et un mot de passe.' });
        }

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ success: false, message: 'Adresse e-mail ou mot de passe incorrect.' });
        }

        if (!user.password) {
            return res.status(400).json({
                success: false,
                message: "Ce compte a été créé avec Google. Veuillez cliquer sur « Se connecter avec Google »."
            });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ success: false, message: 'Adresse e-mail ou mot de passe incorrect.' });
        }

        if (user.accessApprovedAt) {
            return sendAuthenticatedSession(res, user);
        }

        const confirmation = await createAccessConfirmation(user);

        res.json({
            success: true,
            ...confirmation
        });
    } catch (error) {
        console.error('Login error:', error);
        if (error.code === 'EMAIL_DELIVERY_FAILED') {
            return res.status(503).json({
                success: false,
                message: 'Impossible d’envoyer le code de confirmation pour le moment. Veuillez réessayer plus tard.'
            });
        }
        res.status(500).json({ success: false, message: 'Une erreur est survenue sur le serveur.' });
    }
});

// 3. Route de connexion et d’inscription via Google
app.post('/api/google-login', authLimiter, async (req, res) => {
    try {
        const { token } = req.body;

        if (!token) {
            return res.status(400).json({ success: false, message: 'Jeton Google manquant.' });
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

        if (user.accessApprovedAt) {
            return sendAuthenticatedSession(res, user);
        }

        const confirmation = await createAccessConfirmation(user);

        res.json({
            success: true,
            ...confirmation
        });

    } catch (error) {
        console.error(error);
        if (error.code === 'EMAIL_DELIVERY_FAILED') {
            return res.status(503).json({
                success: false,
                message: 'Impossible d’envoyer le code de confirmation pour le moment. Veuillez réessayer plus tard.'
            });
        }
        res.status(400).json({ success: false, message: 'Le jeton Google est invalide.' });
    }
});

app.post('/api/auth/confirm-access', accessCodeLimiter, async (req, res) => {
    try {
        const challengeId = String(req.body?.challengeId || '');
        const code = String(req.body?.code || '').trim();
        if (!/^[a-f0-9]{48}$/.test(challengeId) || !/^\d{6}$/.test(code)) {
            return res.status(400).json({ success: false, message: 'Code de confirmation invalide ou expiré.' });
        }

        const challenge = await AccessConfirmation.findOne({ challengeId });
        if (!challenge || challenge.expiresAt <= new Date() || challenge.attempts >= 5) {
            if (challenge) await AccessConfirmation.deleteOne({ _id: challenge._id });
            return res.status(400).json({ success: false, message: 'Code de confirmation invalide ou expiré.' });
        }

        const submittedHash = Buffer.from(hashResetCode(code), 'hex');
        const expectedHash = Buffer.from(challenge.codeHash, 'hex');
        const isCorrectCode = submittedHash.length === expectedHash.length
            && crypto.timingSafeEqual(submittedHash, expectedHash);
        if (!isCorrectCode) {
            challenge.attempts += 1;
            if (challenge.attempts >= 5) await challenge.deleteOne();
            else await challenge.save();
            return res.status(400).json({ success: false, message: 'Code de confirmation invalide ou expiré.' });
        }

        const user = await User.findById(challenge.userId)
            .select('_id name email nameOnCertificate phone location registeredCourse accessApprovedAt');
        await AccessConfirmation.deleteOne({ _id: challenge._id });
        if (!user) {
            return res.status(404).json({ success: false, message: 'Compte utilisateur introuvable.' });
        }

        if (!user.accessApprovedAt) {
            user.accessApprovedAt = new Date();
            await user.save();
        }
        sendAuthenticatedSession(res, user);
    } catch (error) {
        console.error('Confirm login access error:', error);
        res.status(500).json({ success: false, message: 'Impossible de confirmer cette connexion.' });
    }
});

// 4. Route de demande d’un code de récupération (envoi du code à 6 chiffres)
app.post('/api/forgot-password', resetRequestLimiter, async (req, res) => {
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

        await sendEmail(mailOptions);
        return res.json({ success: true, message: 'Un code à 6 chiffres a été envoyé sur votre email !' });

    } catch (error) {
        console.error("Erreur d'envoi d'email:", error);
        const status = error.code === 'EMAIL_DELIVERY_FAILED' ? 503 : 500;
        return res.status(status).json({ success: false, message: "Erreur lors de l'envoi de l'email." });
    }
});

// 5. Route de vérification du code et de changement du mot de passe
app.post('/api/reset-password-code', resetVerificationLimiter, async (req, res) => {
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

app.get('/api/course-videos/:videoId', authenticate, async (req, res) => {
    try {
        const videoId = String(req.params.videoId || '');
        const courseId = getCourseForVideo(videoId);
        const filename = COURSE_VIDEO_FILES[videoId];
        if (!courseId || !filename) {
            return res.status(404).json({ success: false, message: 'Vidéo de formation introuvable.' });
        }

        const hasCourseAccess = await CourseEnrollmentAccess.exists({ userId: req.user.id, courseId });
        const progress = await CourseProgress.findOne({ userId: req.user.id });
        if (!hasCourseAccess || !progress?.unlockedVideoIds.includes(videoId)) {
            return res.status(403).json({ success: false, message: 'Cette vidéo est verrouillée ou votre accès est inactif.' });
        }

        const filePath = path.resolve(COURSE_VIDEO_DIR, filename);
        const relativePath = path.relative(COURSE_VIDEO_DIR, filePath);
        if (relativePath.startsWith('..') || path.isAbsolute(relativePath)) {
            return res.status(400).json({ success: false, message: 'Chemin de vidéo invalide.' });
        }

        let fileStats;
        try {
            fileStats = await fs.promises.stat(filePath);
        } catch (error) {
            if (error.code === 'ENOENT') {
                return res.status(404).json({ success: false, message: 'Le fichier MP4 de cette formation est introuvable sur le serveur.' });
            }
            throw error;
        }
        if (!fileStats.isFile()) {
            return res.status(404).json({ success: false, message: 'Le fichier MP4 de cette formation est introuvable sur le serveur.' });
        }

        let start = 0;
        let end = fileStats.size - 1;
        const rangeHeader = req.headers.range;
        if (rangeHeader) {
            const match = /^bytes=(\d*)-(\d*)$/.exec(rangeHeader);
            if (!match || (!match[1] && !match[2])) {
                res.setHeader('Content-Range', `bytes */${fileStats.size}`);
                return res.status(416).end();
            }
            if (!match[1]) {
                const suffixLength = Number(match[2]);
                start = Math.max(fileStats.size - suffixLength, 0);
            } else {
                start = Number(match[1]);
                if (match[2]) end = Number(match[2]);
            }
            if (start >= fileStats.size || end < start) {
                res.setHeader('Content-Range', `bytes */${fileStats.size}`);
                return res.status(416).end();
            }
            end = Math.min(end, fileStats.size - 1);
            res.status(206);
            res.setHeader('Content-Range', `bytes ${start}-${end}/${fileStats.size}`);
        }

        res.setHeader('Content-Type', 'video/mp4');
        res.setHeader('Content-Length', end - start + 1);
        res.setHeader('Accept-Ranges', 'bytes');
        res.setHeader('Content-Disposition', 'inline');
        res.setHeader('Cache-Control', 'private, no-store');
        res.setHeader('X-Content-Type-Options', 'nosniff');
        const videoStream = fs.createReadStream(filePath, { start, end });
        videoStream.on('error', (error) => {
            console.error('Course video stream failed:', error);
            if (res.headersSent) res.destroy(error);
            else res.status(500).json({ success: false, message: 'Impossible de lire le fichier vidéo.' });
        });
        videoStream.pipe(res);
    } catch (error) {
        console.error('Serve course video error:', error);
        res.status(500).json({ success: false, message: 'Impossible de charger cette vidéo.' });
    }
});

app.get('/api/course-progress', authenticate, async (req, res) => {
    try {
        const progress = await getOrCreateCourseProgress(req.user.id);
        const accesses = await CourseEnrollmentAccess.find({ userId: req.user.id }).select('courseId');
        const authorizedVideoIds = new Set(
            accesses.flatMap((access) => COURSE_VIDEO_SEQUENCES[access.courseId] || [])
        );
        res.json({
            success: true,
            progress: {
                unlockedVideoIds: progress.unlockedVideoIds.filter((videoId) => authorizedVideoIds.has(videoId)),
                completedVideoIds: progress.completedVideoIds.filter((videoId) => authorizedVideoIds.has(videoId))
            }
        });
    } catch (error) {
        console.error('Get course progress error:', error);
        res.status(500).json({ success: false, message: 'Impossible de charger votre progression.' });
    }
});

app.post('/api/course-progress/start', authenticate, async (req, res) => {
    try {
        const videoId = String(req.body?.videoId || '');
        const courseId = getCourseForVideo(videoId);
        const sequence = courseId ? COURSE_VIDEO_SEQUENCES[courseId] : null;
        if (!courseId || !sequence) {
            return res.status(400).json({ success: false, message: 'Vidéo de formation invalide.' });
        }

        const hasCourseAccess = await CourseEnrollmentAccess.exists({ userId: req.user.id, courseId });
        const progress = await getOrCreateCourseProgress(req.user.id);
        const videoIndex = sequence.indexOf(videoId);
        if (!hasCourseAccess || !progress.unlockedVideoIds.includes(videoId)) {
            return res.status(403).json({ success: false, message: 'Cette vidéo est verrouillée ou votre accès est inactif.' });
        }
        if (videoIndex > 0 && !progress.completedVideoIds.includes(sequence[videoIndex - 1])) {
            return res.status(403).json({ success: false, message: 'Terminez d’abord la vidéo précédente de cette formation.' });
        }

        const watchSession = await VideoWatchSession.create({
            userId: req.user.id,
            videoId,
            courseId,
            expiresAt: new Date(Date.now() + 6 * 60 * 60 * 1000)
        });
        res.status(201).json({ success: true, watchSessionId: watchSession.id });
    } catch (error) {
        console.error('Start course video error:', error);
        res.status(500).json({ success: false, message: 'Impossible de démarrer le suivi de cette vidéo.' });
    }
});

app.post('/api/course-progress/watch', authenticate, async (req, res) => {
    try {
        const videoId = String(req.body?.videoId || '');
        const result = await recordVideoWatchProgress({
            userId: req.user.id,
            videoId,
            watchSessionId: String(req.body?.watchSessionId || ''),
            currentTime: Number(req.body?.currentTime),
            duration: Number(req.body?.duration)
        });
        if (result.error) return res.status(400).json({ success: false, message: result.error });
        res.json({
            success: true,
            progress: {
                furthestPosition: result.watchSession.furthestPosition,
                watchedSeconds: result.watchSession.watchedSeconds,
                duration: result.watchSession.duration
            }
        });
    } catch (error) {
        console.error('Record course video watch progress error:', error);
        res.status(500).json({ success: false, message: 'Impossible d’enregistrer votre progression vidéo.' });
    }
});

app.get('/api/admin/course-access', requireCourseAdmin, async (req, res) => {
    try {
        const email = sanitizeEmail(req.query?.email);
        if (!/^\S+@\S+\.\S+$/.test(email)) {
            return res.status(400).json({ success: false, message: 'Veuillez fournir une adresse e-mail valide.' });
        }

        const user = await User.findOne({ email })
            .select('_id name email nameOnCertificate phone location registeredCourse');
        if (!user) {
            return res.status(404).json({ success: false, message: 'Aucun compte ne correspond à cette adresse e-mail.' });
        }
        const accesses = await CourseEnrollmentAccess.find({ userId: user._id }).select('courseId grantedAt');
        res.json({
            success: true,
            student: {
                name: user.name,
                email: user.email,
                nameOnCertificate: user.nameOnCertificate,
                phone: user.phone,
                location: user.location,
                registeredCourse: user.registeredCourse
            },
            courses: accesses.map((access) => ({
                courseId: access.courseId,
                courseName: COURSE_TITLES[access.courseId],
                grantedAt: access.grantedAt
            }))
        });
    } catch (error) {
        console.error('List course access error:', error);
        res.status(500).json({ success: false, message: 'Impossible de consulter les accès de cet étudiant.' });
    }
});

app.post('/api/admin/course-access', requireCourseAdmin, async (req, res) => {
    try {
        const email = sanitizeEmail(req.body?.email);
        const courseId = String(req.body?.courseId || '');
        if (!/^\S+@\S+\.\S+$/.test(email) || !COURSE_ACCESS_CATEGORIES.includes(courseId)) {
            return res.status(400).json({ success: false, message: 'Veuillez fournir un e-mail et une formation valides.' });
        }

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ success: false, message: 'L’étudiant doit d’abord créer son compte avec cette adresse e-mail.' });
        }

        const granted = await grantCourseAccess(user, courseId);
        res.status(granted ? 201 : 200).json({
            success: true,
            message: granted
                ? `Accès accordé pour ${COURSE_TITLES[courseId]}; le code personnel a été envoyé par e-mail.`
                : `L’accès à ${COURSE_TITLES[courseId]} et son code existant ont été conservés sans changement.`
        });
    } catch (error) {
        console.error('Grant course access error:', error);
        res.status(500).json({ success: false, message: 'Impossible d’accorder l’accès. Vérifiez le service d’e-mail et réessayez.' });
    }
});

app.delete('/api/admin/course-access', requireCourseAdmin, async (req, res) => {
    try {
        const email = sanitizeEmail(req.body?.email);
        const courseId = String(req.body?.courseId || '');
        if (!/^\S+@\S+\.\S+$/.test(email) || !COURSE_ACCESS_CATEGORIES.includes(courseId)) {
            return res.status(400).json({ success: false, message: 'Veuillez fournir un e-mail et une formation valides.' });
        }

        const user = await User.findOne({ email }).select('_id');
        if (!user) {
            return res.status(404).json({ success: false, message: 'Aucun compte ne correspond à cette adresse e-mail.' });
        }
        const result = await CourseEnrollmentAccess.deleteOne({ userId: user._id, courseId });
        if (!result.deletedCount) {
            return res.status(404).json({ success: false, message: 'Cet étudiant n’a pas d’accès actif à cette formation.' });
        }

        const courseVideoIds = COURSE_VIDEO_SEQUENCES[courseId] || [];
        await CourseProgress.updateOne(
            { userId: user._id },
            { $pull: { unlockedVideoIds: { $in: courseVideoIds }, completedVideoIds: { $in: courseVideoIds } } }
        );
        res.json({ success: true, message: `L’accès à ${COURSE_TITLES[courseId]} a été révoqué.` });
    } catch (error) {
        console.error('Revoke course access error:', error);
        res.status(500).json({ success: false, message: 'Impossible de révoquer cet accès.' });
    }
});

app.post('/api/course-access/verify', authenticate, async (req, res) => {
    try {
        const category = String(req.body?.category || '');
        const accessCode = String(req.body?.accessCode || '').trim();
        if (!COURSE_ACCESS_CATEGORIES.includes(category) || !await isValidCourseAccessCode(req.user.id, category, accessCode)) {
            return res.status(400).json({ success: false, message: 'Code d’accès incorrect ou expiré.' });
        }
        res.json({ success: true });
    } catch (error) {
        console.error('Verify course access code error:', error);
        res.status(500).json({ success: false, message: 'Impossible de vérifier le code d’accès.' });
    }
});

app.post('/api/course-progress/unlock', authenticate, async (req, res) => {
    try {
        const videoId = String(req.body?.videoId || '');
        const accessCode = String(req.body?.accessCode || '').trim();
        const courseId = getCourseForVideo(videoId);
        const sequence = courseId ? COURSE_VIDEO_SEQUENCES[courseId] : null;
        if (!courseId || !sequence || !accessCode || accessCode.length > 128) {
            return res.status(400).json({ success: false, message: 'Code d’accès incorrect.' });
        }

        if (!await isValidCourseAccessCode(req.user.id, courseId, accessCode)) {
            return res.status(400).json({ success: false, message: 'Code d’accès incorrect ou expiré.' });
        }

        const progress = await getOrCreateCourseProgress(req.user.id);
        const videoIndex = sequence.indexOf(videoId);
        const previousVideoId = sequence[videoIndex - 1];
        if (videoIndex > 0 && !progress.completedVideoIds.includes(previousVideoId)) {
            return res.status(403).json({ success: false, message: 'Terminez d’abord la vidéo précédente de cette formation.' });
        }
        progress.unlockedVideoIds.addToSet(videoId);
        await progress.save();
        res.json({ success: true, progress: serializeCourseProgress(progress) });
    } catch (error) {
        console.error('Unlock course video error:', error);
        res.status(500).json({ success: false, message: 'Impossible de débloquer cette vidéo.' });
    }
});

app.post('/api/course-progress/complete', authenticate, async (req, res) => {
    try {
        const videoId = String(req.body?.videoId || '');
        const courseId = getCourseForVideo(videoId);
        const sequence = courseId ? COURSE_VIDEO_SEQUENCES[courseId] : null;
        if (!courseId || !sequence) {
            return res.status(400).json({ success: false, message: 'Vidéo de formation invalide.' });
        }

        const progress = await getOrCreateCourseProgress(req.user.id);
        const hasCourseAccess = await CourseEnrollmentAccess.exists({ userId: req.user.id, courseId });
        if (!hasCourseAccess) {
            return res.status(403).json({ success: false, message: 'Vous n’avez pas d’accès actif à cette formation.' });
        }
        if (!progress.unlockedVideoIds.includes(videoId)) {
            return res.status(403).json({ success: false, message: 'Cette vidéo est encore verrouillée.' });
        }

        const watchResult = await recordVideoWatchProgress({
            userId: req.user.id,
            videoId,
            watchSessionId: String(req.body?.watchSessionId || ''),
            currentTime: Number(req.body?.currentTime),
            duration: Number(req.body?.duration)
        });
        if (watchResult.error) {
            return res.status(400).json({ success: false, message: watchResult.error });
        }
        const watchSession = watchResult.watchSession;
        if (watchSession.furthestPosition < watchSession.duration - 1.5
            || watchSession.watchedSeconds < watchSession.duration * 0.95) {
            return res.status(403).json({ success: false, message: 'Regardez cette vidéo jusqu’à la fin pour débloquer la suite.' });
        }

        progress.completedVideoIds.addToSet(videoId);
        const videoIndex = sequence.indexOf(videoId);
        const nextVideoId = sequence[videoIndex + 1];
        if (nextVideoId) progress.unlockedVideoIds.addToSet(nextVideoId);
        await progress.save();
        await VideoWatchSession.deleteOne({ _id: watchSession._id });
        res.json({ success: true, progress: serializeCourseProgress(progress) });
    } catch (error) {
        console.error('Complete course video error:', error);
        res.status(500).json({ success: false, message: 'Impossible d’enregistrer la fin de cette vidéo.' });
    }
});

app.post('/api/me/certificate-profile', authenticate, async (req, res) => {
    try {
        const nameOnCertificate = String(req.body?.nameOnCertificate || '').trim();
        const phone = String(req.body?.phone || '').trim();
        const location = String(req.body?.location || '').trim();
        const registeredCourse = String(req.body?.registeredCourse || '');

        if (!nameOnCertificate || nameOnCertificate.length > 100
            || !/^[+0-9().\-\s]{7,30}$/.test(phone)
            || location.length < 2 || location.length > 100
            || !COURSE_ACCESS_CATEGORIES.includes(registeredCourse)) {
            return res.status(400).json({ success: false, message: 'Vérifiez les informations demandées pour le certificat.' });
        }

        const user = await User.findByIdAndUpdate(
            req.user.id,
            { nameOnCertificate, phone, location, registeredCourse },
            { new: true, runValidators: true }
        ).select('_id name email nameOnCertificate phone location registeredCourse');
        if (!user) {
            return res.status(404).json({ success: false, message: 'Utilisateur introuvable.' });
        }
        res.json({
            success: true,
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                nameOnCertificate: user.nameOnCertificate,
                phone: user.phone,
                location: user.location,
                registeredCourse: user.registeredCourse
            }
        });
    } catch (error) {
        console.error('Save certificate profile error:', error);
        res.status(500).json({ success: false, message: 'Impossible d’enregistrer les informations du certificat.' });
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
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                nameOnCertificate: user.nameOnCertificate,
                phone: user.phone,
                location: user.location,
                registeredCourse: user.registeredCourse
            }
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

// Count authenticated students, not browser tabs or devices.
const onlineUsers = new Map();

io.on('connection', (socket) => {
    const userId = socket.data.userId;
    const userSockets = onlineUsers.get(userId) || new Set();
    userSockets.add(socket.id);
    onlineUsers.set(userId, userSockets);
    io.emit('onlineCount', onlineUsers.size);

    socket.on('disconnect', () => {
        const activeSockets = onlineUsers.get(userId);
        if (activeSockets) {
            activeSockets.delete(socket.id);
            if (activeSockets.size === 0) onlineUsers.delete(userId);
        }
        io.emit('onlineCount', onlineUsers.size);
    });
});

// Démarrage du serveur après connexion à MongoDB
const startServer = async () => {
    const requiredEnvironment = {
        JWT_SECRET,
        MONGODB_URI,
        GOOGLE_CLIENT_ID,
        FRONTEND_URLS: FRONTEND_URLS.join(',')
    };
    const missingEnvironment = Object.keys(requiredEnvironment).filter((key) => !requiredEnvironment[key]);
    const hasBrevoConfiguration = Boolean(process.env.BREVO_API_KEY && process.env.BREVO_SENDER_EMAIL);
    const hasResendConfiguration = Boolean(process.env.RESEND_API_KEY && process.env.EMAIL_FROM);
    const hasSmtpConfiguration = Boolean(process.env.EMAIL_USER && process.env.EMAIL_PASS);
    if (!hasBrevoConfiguration && !hasResendConfiguration && !hasSmtpConfiguration) {
        missingEnvironment.push('BREVO_API_KEY and BREVO_SENDER_EMAIL (or Resend or SMTP credentials)');
    }
    if (!process.env.ACCESS_APPROVAL_EMAIL && !process.env.EMAIL_USER) {
        missingEnvironment.push('ACCESS_APPROVAL_EMAIL');
    }
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
