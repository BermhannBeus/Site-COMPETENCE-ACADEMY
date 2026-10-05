if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config();
}

const express = require('express');
const http = require('http');
const crypto = require('crypto');
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
const getAdminNotificationEmails = () => {
    const recipients = [...new Set([
        process.env.ACCESS_APPROVAL_EMAIL,
        process.env.EMAIL_USER
    ].map(sanitizeEmail).filter(Boolean))];
    if (!recipients.length || recipients.some((email) => !/^\S+@\S+\.\S+$/.test(email))) {
        const error = new Error('Configure a valid ACCESS_APPROVAL_EMAIL or EMAIL_USER for admin code notifications.');
        error.code = 'EMAIL_DELIVERY_FAILED';
        throw error;
    }
    return recipients;
};
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
                    ...(mailOptions.bcc ? {
                        bcc: (Array.isArray(mailOptions.bcc) ? mailOptions.bcc : [mailOptions.bcc])
                            .map((recipient) => typeof recipient === 'string'
                                ? { email: recipient }
                                : recipient)
                    } : {}),
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
                    ...(mailOptions.bcc ? { bcc: mailOptions.bcc } : {}),
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

const getFrontendUrl = (path, fragmentValues = {}) => {
    const configuredOrigin = FRONTEND_URLS
        .map((candidate) => {
            try {
                return new URL(candidate);
            } catch (error) {
                return null;
            }
        })
        .find((candidate) => candidate
            && candidate.protocol === 'https:'
            && /\.[a-z]{2,}$/i.test(candidate.hostname)
            && !candidate.hostname.endsWith('.local')
            && !/^(localhost|127(?:\.\d{1,3}){3}|\[::1\])$/i.test(candidate.hostname))
        ?.origin || 'https://competenceacademy.netlify.app';
    const url = new URL(path, `${configuredOrigin.replace(/\/+$/, '')}/`);
    const fragment = new URLSearchParams(fragmentValues).toString();
    if (fragment) url.hash = fragment;
    return url.toString();
};

const escapeHtml = (value) => String(value).replace(/[&<>"']/g, (character) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
})[character]);

const createCodeEmail = ({ greeting, message, code, buttonLabel, buttonUrl, note }) => ({
    text: `${greeting}\n\n${message}\n\n${code}\n\n${note}\n\nOuvrir la page : ${buttonUrl}\n\nCompetence Academy`,
    html: `
        <div style="margin:0;background:#f3f6fb;padding:28px 12px;font-family:Arial,sans-serif;color:#1e293b;">
            <div style="max-width:520px;margin:0 auto;border:1px solid #dbe3ee;border-radius:14px;background:#ffffff;overflow:hidden;">
                <div style="padding:22px 24px;background:#111e62;color:#ffffff;text-align:center;">
                    <div style="font-size:20px;font-weight:800;letter-spacing:1px;">COMPETENCE ACADEMY</div>
                </div>
                <div style="padding:24px;">
                    <p style="margin:0 0 14px;">${escapeHtml(greeting)}</p>
                    <p style="margin:0 0 20px;line-height:1.6;">${escapeHtml(message)}</p>
                    <div style="margin:0 0 22px;padding:16px;border:1px solid #dbeafe;border-radius:10px;background:#eff6ff;text-align:center;">
                        <div style="margin-bottom:7px;color:#64748b;font-size:12px;text-transform:uppercase;letter-spacing:1px;">Votre code</div>
                        <div style="color:#111e62;font-size:24px;font-weight:800;letter-spacing:2px;overflow-wrap:anywhere;">${escapeHtml(code)}</div>
                    </div>
                    <table role="presentation" border="0" cellpadding="0" cellspacing="0" style="margin:0 auto 20px;">
                        <tr><td align="center" bgcolor="#f76b00" style="border-radius:8px;">
                            <a href="${escapeHtml(buttonUrl)}" style="display:inline-block;padding:13px 22px;border:1px solid #f76b00;border-radius:8px;color:#ffffff;font-weight:700;text-decoration:none;">${escapeHtml(buttonLabel)}</a>
                        </td></tr>
                    </table>
                    <p style="margin:0;color:#64748b;font-size:13px;line-height:1.6;">${escapeHtml(note)}</p>
                </div>
                <div style="padding:14px 20px;border-top:1px solid #e2e8f0;color:#64748b;font-size:12px;text-align:center;">Competence Academy — Formation pratique et professionnelle</div>
            </div>
        </div>
    `
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
const getCourseForVideo = (videoId) => {
    const existingCourse = COURSE_ACCESS_CATEGORIES.find(
        (courseId) => COURSE_VIDEO_SEQUENCES[courseId].includes(videoId)
    );
    if (existingCourse) return existingCourse;

    return COURSE_ACCESS_CATEGORIES.find((courseId) => {
        const match = new RegExp(`^${courseId}-([2-9]|[1-9]\\d+)$`).exec(videoId);
        return Boolean(match && Number.isSafeInteger(Number(match[1])));
    });
};
const getCourseVideoIndex = (courseId, videoId) => {
    const knownIndex = COURSE_VIDEO_SEQUENCES[courseId]?.indexOf(videoId) ?? -1;
    if (knownIndex >= 0) return knownIndex;

    const match = new RegExp(`^${courseId}-([2-9]|[1-9]\\d+)$`).exec(videoId);
    if (!match) return -1;
    const stepNumber = Number(match[1]);
    return Number.isSafeInteger(stepNumber) ? stepNumber - 1 : -1;
};
const getCourseVideoId = (courseId, videoIndex) => COURSE_VIDEO_SEQUENCES[courseId]?.[videoIndex]
    || (videoIndex > 0 ? `${courseId}-${videoIndex + 1}` : null);

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
    encryptedCode: { type: String, default: '', select: false },
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

const generateCourseAccessCode = (courseId = '') => {
    const prefix = String(courseId || 'CA').toUpperCase().replace(/[^A-Z]/g, '').slice(0, 4) || 'CA';
    const randomPart = crypto.randomBytes(8).toString('hex').toUpperCase();
    return `${prefix}-${randomPart}`;
};

const getCourseAccessCodeEncryptionKey = () => crypto.createHash('sha256')
    .update(`course-access-code:${JWT_SECRET}`)
    .digest();
const encryptCourseAccessCode = (code) => {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', getCourseAccessCodeEncryptionKey(), iv);
    const encrypted = Buffer.concat([cipher.update(code, 'utf8'), cipher.final()]);
    return [iv, cipher.getAuthTag(), encrypted].map((part) => part.toString('base64url')).join('.');
};
const decryptCourseAccessCode = (encryptedCode) => {
    const [ivValue, authTagValue, encryptedValue, ...extra] = String(encryptedCode || '').split('.');
    if (!ivValue || !authTagValue || !encryptedValue || extra.length) {
        throw new Error('Stored course access code has an invalid encrypted format.');
    }
    const decipher = crypto.createDecipheriv(
        'aes-256-gcm',
        getCourseAccessCodeEncryptionKey(),
        Buffer.from(ivValue, 'base64url')
    );
    decipher.setAuthTag(Buffer.from(authTagValue, 'base64url'));
    return Buffer.concat([
        decipher.update(Buffer.from(encryptedValue, 'base64url')),
        decipher.final()
    ]).toString('utf8');
};

const issueCourseAccessCode = async (user, courseId) => {
    const code = generateCourseAccessCode(courseId);
    const grantedAt = new Date();
    const encryptedCode = encryptCourseAccessCode(code);
    const existingAccess = await CourseEnrollmentAccess.findOne({ userId: user._id, courseId })
        .select('+encryptedCode');
    const previousCodeHash = existingAccess?.codeHash;
    const previousEncryptedCode = existingAccess?.encryptedCode;
    const previousGrantedAt = existingAccess?.grantedAt;

    if (existingAccess) {
        existingAccess.codeHash = hashResetCode(code);
        existingAccess.encryptedCode = encryptedCode;
        existingAccess.grantedAt = grantedAt;
        await existingAccess.save();
    } else {
        await CourseEnrollmentAccess.create({
            userId: user._id,
            courseId,
            codeHash: hashResetCode(code),
            encryptedCode,
            grantedAt
        });
    }

    try {
        const adminCopyEmails = getAdminNotificationEmails().filter((email) => email !== user.email);
        const courseUrl = getFrontendUrl('/Cours%20en%20Ligne.html', {
            'access-code': code,
            course: courseId
        });
        const emailContent = createCodeEmail({
            greeting: `Bonjour ${user.name},`,
            message: `Voici votre code personnel pour la formation « ${COURSE_TITLES[courseId]} ». Appuyez sur le bouton pour ouvrir le cours avec le code déjà préparé.`,
            code,
            buttonLabel: 'Ouvrir le cours',
            buttonUrl: courseUrl,
            note: 'Le code est personnel et reste valable tant que votre accès à la formation est actif. Si vous n’êtes pas déjà connecté(e), connectez-vous : le code restera prêt dans le cours.'
        });
        await sendEmail({
            to: user.email,
            ...(adminCopyEmails.length ? { bcc: adminCopyEmails } : {}),
            subject: `Votre code d’accès - ${COURSE_TITLES[courseId]} | Competence Academy`,
            ...emailContent
        });
    } catch (error) {
        if (existingAccess) {
            existingAccess.codeHash = previousCodeHash;
            existingAccess.encryptedCode = previousEncryptedCode || '';
            existingAccess.grantedAt = previousGrantedAt;
            await existingAccess.save();
        } else {
            await CourseEnrollmentAccess.deleteOne({ userId: user._id, courseId });
        }
        throw error;
    }

    return code;
};

const grantCourseAccess = async (user, courseId) => {
    const existingAccess = await CourseEnrollmentAccess.findOne({ userId: user._id, courseId });
    if (existingAccess) return false;
    await issueCourseAccessCode(user, courseId);
    return true;
};

const createAccessConfirmation = async (user) => {
    const approvalEmails = getAdminNotificationEmails();

    const code = getStudentAccessOtp(user);
    const challengeId = crypto.randomBytes(24).toString('hex');
    const expiresAt = new Date(Date.now() + 20 * 60 * 1000);
    const confirmationUrl = getFrontendUrl('/Login.html');
    await AccessConfirmation.findOneAndUpdate(
        { userId: user._id },
        { challengeId, codeHash: hashResetCode(code), attempts: 0, expiresAt },
        { upsert: true, new: true, setDefaultsOnInsert: true }
    );
    try {
        await sendEmail({
            to: approvalEmails,
            subject: 'Demande de confirmation de connexion - Competence Academy',
            ...createCodeEmail({
                greeting: 'Bonjour,',
                message: `Nouvelle demande de confirmation de connexion pour ${user.name} (${user.email}). Transmettez ce code à l’étudiant pour qu’il le saisisse dans sa session de connexion.`,
                code,
                buttonLabel: 'Ouvrir la page de connexion',
                buttonUrl: confirmationUrl,
                note: 'Ne saisissez pas ce code sur votre propre session : il confirme la connexion de l’étudiant. Le code expire dans 20 minutes.'
            })
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
    const configuredKey = String(process.env.COURSE_ADMIN_API_KEY || '').trim();
    if (!configuredKey) {
        return res.status(503).json({ success: false, message: 'L’administration des accès aux cours n’est pas configurée.' });
    }

    const keyHeader = String(req.get('x-course-admin-key') || '');
    let submittedKey = keyHeader;
    if (keyHeader.startsWith('utf8:')) {
        const encodedKey = keyHeader.slice(5);
        if (!/^[A-Za-z0-9_-]+$/.test(encodedKey)) {
            return res.status(401).json({ success: false, message: 'Accès administrateur refusé.' });
        }
        submittedKey = Buffer.from(encodedKey, 'base64url').toString('utf8');
    }
    submittedKey = submittedKey.trim();
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
            ...createCodeEmail({
                greeting: 'Bonjour,',
                message: 'Voici votre code de vérification pour réinitialiser votre mot de passe. Appuyez sur le bouton pour ouvrir le formulaire avec votre adresse e-mail et le code déjà renseignés.',
                code: resetCode,
                buttonLabel: 'Réinitialiser mon mot de passe',
                buttonUrl: getFrontendUrl('/Login.html', {
                    'reset-code': resetCode,
                    email
                }),
                note: 'Le code expire dans 10 minutes. Vous devrez encore choisir un nouveau mot de passe pour terminer la réinitialisation.'
            })
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

app.get('/api/course-progress', authenticate, async (req, res) => {
    try {
        const progress = await getOrCreateCourseProgress(req.user.id);
        const accesses = await CourseEnrollmentAccess.find({ userId: req.user.id }).select('courseId');
        const authorizedCourseIds = new Set(accesses.map((access) => access.courseId));
        const isAuthorizedVideo = (videoId) => {
            const courseId = getCourseForVideo(videoId);
            return courseId && authorizedCourseIds.has(courseId);
        };
        res.json({
            success: true,
            progress: {
                unlockedVideoIds: progress.unlockedVideoIds.filter(isAuthorizedVideo),
                completedVideoIds: progress.completedVideoIds.filter(isAuthorizedVideo)
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
        const videoIndex = getCourseVideoIndex(courseId, videoId);
        if (videoIndex < 0) {
            return res.status(400).json({ success: false, message: 'Vidéo de formation invalide.' });
        }
        const previousVideoId = videoIndex > 0 ? getCourseVideoId(courseId, videoIndex - 1) : null;
        if (!hasCourseAccess || !progress.unlockedVideoIds.includes(videoId)) {
            return res.status(403).json({ success: false, message: 'Cette vidéo est verrouillée ou votre accès est inactif.' });
        }
        if (previousVideoId && !progress.completedVideoIds.includes(previousVideoId)) {
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

app.get('/api/admin/course-access/code', requireCourseAdmin, async (req, res) => {
    try {
        const email = sanitizeEmail(req.query?.email);
        const courseId = String(req.query?.courseId || '');
        if (!/^\S+@\S+\.\S+$/.test(email) || !COURSE_ACCESS_CATEGORIES.includes(courseId)) {
            return res.status(400).json({ success: false, message: 'Veuillez fournir un e-mail et une formation valides.' });
        }

        const user = await User.findOne({ email }).select('_id');
        if (!user) {
            return res.status(404).json({ success: false, message: 'Aucun compte ne correspond à cette adresse e-mail.' });
        }
        const access = await CourseEnrollmentAccess.findOne({ userId: user._id, courseId })
            .select('+encryptedCode');
        if (!access) {
            return res.status(404).json({ success: false, message: 'Cet étudiant n’a pas d’accès actif à cette formation.' });
        }
        if (!access.encryptedCode) {
            return res.status(409).json({
                success: false,
                message: 'Ce code a été créé avant l’activation de sa sauvegarde chiffrée et ne peut pas être récupéré. Il faut le renouveler une seule fois.'
            });
        }

        res.json({ success: true, code: decryptCourseAccessCode(access.encryptedCode) });
    } catch (error) {
        console.error('Read course access code error:', error);
        res.status(500).json({ success: false, message: 'Impossible de consulter le code de cette formation.' });
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

app.post('/api/admin/course-access/code', requireCourseAdmin, async (req, res) => {
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

        const code = await issueCourseAccessCode(user, courseId);
        res.json({
            success: true,
            code,
            message: `Le code de ${COURSE_TITLES[courseId]} a été créé et envoyé à ${user.email}. L’ancien code, s’il existait, ne fonctionne plus.`
        });
    } catch (error) {
        console.error('Issue course access code error:', error);
        res.status(500).json({ success: false, message: 'Impossible de créer ou d’envoyer le code. Le code précédent reste actif si l’envoi a échoué.' });
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

        const courseVideoIds = [
            ...(COURSE_VIDEO_SEQUENCES[courseId] || []),
            new RegExp(`^${courseId}-([2-9]|[1-9]\\d+)$`)
        ];
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
        const videoIndex = getCourseVideoIndex(courseId, videoId);
        if (videoIndex < 0) {
            return res.status(400).json({ success: false, message: 'Vidéo de formation invalide.' });
        }
        const previousVideoId = videoIndex > 0 ? getCourseVideoId(courseId, videoIndex - 1) : null;
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
        const videoIndex = getCourseVideoIndex(courseId, videoId);
        const nextVideoId = getCourseVideoId(courseId, videoIndex + 1);
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
