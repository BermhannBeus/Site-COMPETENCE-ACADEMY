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
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');
const nodemailer = require('nodemailer');

const getTranzakApiBaseUrl = () => {
    const configuredUrl = String(process.env.TRANZAK_API_URL || 'https://api.tranzak.co').trim();
    const parsedUrl = new URL(configuredUrl);
    if (parsedUrl.protocol !== 'https:' || parsedUrl.search || parsedUrl.hash
        || parsedUrl.username || parsedUrl.password) {
        throw new Error('TRANZAK_API_URL must be an HTTPS base URL without credentials, query, or fragment.');
    }
    return parsedUrl.toString().replace(/\/+$/, '');
};
const getTranzakPaymentsUrl = () => `${getTranzakApiBaseUrl()}/api/gateway/v1/payments`;
const getTranzakHeaders = (apiKey) => ({
    'X-Api-Key': apiKey,
    Accept: 'application/json',
    'Content-Type': 'application/json'
});

const app = express();
const server = http.createServer(app);
app.set('trust proxy', 1);
const io = new Server(server, {
    cors: {
        origin: (origin, callback) => {
            if (isAllowedOrigin(origin)) {
                callback(null, true);
                return;
            }
            callback(new Error('Not allowed by CORS'));
        },
        methods: ["GET", "POST"],
        credentials: true
    }
});

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_JWT_SECRET = process.env.ADMIN_JWT_SECRET;
const JWT_EXPIRES_IN = '1h';
const ADMIN_JWT_EXPIRES_IN = '1h';
const ADMIN_OTP_TTL_MS = 2 * 60 * 1000;
const ADMIN_OTP_RESEND_INTERVAL_MS = ADMIN_OTP_TTL_MS;
const ADMIN_OTP_MAX_ATTEMPTS = 5;
const ACCESS_CONFIRMATION_TTL_MS = 10 * 60 * 1000;
const ACCESS_CONFIRMATION_RESEND_INTERVAL_MS = 5 * 60 * 1000;
const ACCESS_CONFIRMATION_MAX_ATTEMPTS = 3;
const ACCESS_CONFIRMATION_LOCKOUT_MS = 10 * 60 * 1000;
const ACCESS_CONFIRMATION_MAX_REQUESTS = 5;
const ACCESS_CONFIRMATION_REQUEST_LOCKOUT_MS = 15 * 60 * 1000;
const SIGNUP_MAX_FAILED_ATTEMPTS = 3;
const LOGIN_MAX_FAILED_ATTEMPTS = 3;
const LOGIN_LOCKOUT_MS = 10 * 60 * 1000;
const PASSWORD_RESET_MAX_ATTEMPTS = 3;
const PASSWORD_RESET_LOCKOUT_MS = 10 * 60 * 1000;
const PASSWORD_RESET_CODE_TTL_MS = 15 * 60 * 1000;
const SESSION_IDLE_TIMEOUT_MS = 15 * 60 * 1000;
const SESSION_TOKEN_LIFETIME_MS = 60 * 60 * 1000;
const MONGODB_URI = process.env.MONGODB_URI;
const FRONTEND_URLS = String(process.env.FRONTEND_URLS || process.env.FRONTEND_URL || '')
    .split(',')
    .map((url) => url.trim().replace(/\/$/, ''))
    .filter(Boolean);

const developmentOrigins = [
    'http://localhost',
    'http://localhost:5000',
    'http://127.0.0.1',
    'http://127.0.0.1:5000'
];
const isDevelopmentHostname = (hostname) => /^(localhost|127(?:\.\d{1,3}){3}|0\.0\.0\.0|\[?::1\]?)$/i.test(hostname)
    || hostname.endsWith('.localhost')
    || hostname.endsWith('.local');
const productionOrigins = [...new Set(FRONTEND_URLS.flatMap((frontendUrl) => {
    try {
        const parsedUrl = new URL(frontendUrl);
        return parsedUrl.protocol === 'https:' && !isDevelopmentHostname(parsedUrl.hostname)
            ? [parsedUrl.origin]
            : [];
    } catch (error) {
        return [];
    }
}))];
const allowedOrigins = process.env.NODE_ENV === 'production'
    ? productionOrigins
    : [...new Set([...developmentOrigins, ...FRONTEND_URLS])];
const isAllowedOrigin = (origin) => !origin || allowedOrigins.includes(origin);

io.use(async (socket, next) => {
    const cookieHeader = socket.handshake.headers.cookie || '';
    const authCookie = cookieHeader.split(';').map((cookie) => cookie.trim())
        .find((cookie) => cookie.startsWith('ca_token='));
    const token = authCookie ? authCookie.slice('ca_token='.length) : '';

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        if (!decoded.id || decoded.accessConfirmed !== true) {
            return next(new Error('Authentication required'));
        }
        const user = await User.findById(decoded.id)
            .select('tokenVersion activeSessionId activeSessionExpiresAt activeSessionTokenExpiresAt');
        if (!user || decoded.tokenVersion !== user.tokenVersion
            || decoded.sessionId !== user.activeSessionId
            || !user.activeSessionExpiresAt
            || user.activeSessionExpiresAt <= new Date()
            || (user.activeSessionTokenExpiresAt && user.activeSessionTokenExpiresAt <= new Date())) {
            return next(new Error('Authentication required'));
        }
        socket.data.userId = String(decoded.id);
        socket.data.sessionId = decoded.sessionId;
        socket.data.tokenVersion = decoded.tokenVersion;
        socket.data.sessionExpiresAt = user.activeSessionExpiresAt.getTime();
        socket.data.sessionTokenExpiresAt = user.activeSessionTokenExpiresAt?.getTime()
            || user.activeSessionExpiresAt.getTime();
        await socket.join(socket.data.userId);
        next();
    } catch (error) {
        next(new Error('Authentication required'));
    }
});

// Client ID Google
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const client = new OAuth2Client(GOOGLE_CLIENT_ID);

const sanitizeEmail = (value = '') => String(value).trim().toLowerCase();
const getAllowedAdminEmails = () => String(process.env.ALLOWED_ADMIN_EMAILS || '')
    .split(',')
    .map(sanitizeEmail)
    .filter(Boolean);
const isAllowedAdminEmail = (email) => getAllowedAdminEmails().includes(sanitizeEmail(email));
const adminOtpChallenges = new Map();
const adminOtpLastSentAt = new Map();
const accessConfirmationRequestCooldowns = new Map();
const accessConfirmationRequestLimiter = new Map();
const adminOtpRequestLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 5,
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, message: 'Trop de demandes de code. Réessayez plus tard.' }
});
const adminOtpVerifyLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 20,
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, message: 'Trop de tentatives. Réessayez plus tard.' }
});
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
const ACTIVE_SESSION_CONFLICT_MESSAGE = 'Vous êtes déjà connecté sur un autre appareil. Nouvelle connexion refusée.';
const hasActiveSession = (userId) => {
    const now = new Date();
    return User.exists({
        _id: userId,
        activeSessionId: { $nin: [null, ''] },
        activeSessionExpiresAt: { $gt: now },
        isLoggedIn: { $ne: false },
        $or: [
            { activeSessionTokenExpiresAt: { $gt: now } },
            { activeSessionTokenExpiresAt: { $exists: false } },
            { activeSessionTokenExpiresAt: null }
        ]
    });
};
const sendAuthenticatedSession = async (res, user) => {
    const now = new Date();
    const sessionId = crypto.randomUUID();
    const tokenExpiresAt = new Date(
        Math.floor(now.getTime() / 1000) * 1000 + SESSION_TOKEN_LIFETIME_MS
    );
    const activeUser = await User.findOneAndUpdate({
        _id: user._id,
        $or: [
            { isLoggedIn: false },
            { activeSessionId: { $in: [null, ''] } },
            { activeSessionExpiresAt: { $lte: now } },
            { activeSessionExpiresAt: null },
            { activeSessionExpiresAt: { $exists: false } },
            { activeSessionTokenExpiresAt: { $lte: now } }
        ]
    }, {
        $inc: { tokenVersion: 1 },
        $set: {
            isLoggedIn: true,
            activeSessionId: sessionId,
            activeSessionExpiresAt: new Date(Math.min(now.getTime() + SESSION_IDLE_TIMEOUT_MS, tokenExpiresAt.getTime())),
            activeSessionTokenExpiresAt: tokenExpiresAt
        }
    }, { new: true }).select('_id name email avatarUrl nameOnCertificate phone location registeredCourse tokenVersion');
    if (!activeUser) {
        return res.status(401).json({
            success: false,
            message: ACTIVE_SESSION_CONFLICT_MESSAGE
        });
    }
    io.in(String(activeUser._id)).disconnectSockets(true);
    const token = jwt.sign(
        {
            id: activeUser.id,
            email: activeUser.email,
            accessConfirmed: true,
            tokenVersion: activeUser.tokenVersion,
            sessionId
        },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRES_IN }
    );
    setAuthCookie(res, token);
    const serializedUser = {
        id: activeUser.id,
        name: activeUser.name,
        email: activeUser.email,
        avatarUrl: activeUser.avatarUrl,
        nameOnCertificate: activeUser.nameOnCertificate,
        phone: activeUser.phone,
        location: activeUser.location,
        registeredCourse: activeUser.registeredCourse
    };
    return res.json({
        success: true,
        authenticated: true,
        user: serializedUser,
        profileComplete: Boolean(
            activeUser.nameOnCertificate && activeUser.phone && activeUser.location && activeUser.registeredCourse
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
        <div style="margin:0;background:#f3f6fb;padding:28px 12px;font-family:Arial,sans-serif;color:#000641;">
            <div style="max-width:520px;margin:0 auto;border:1px solid #dbe3ee;border-radius:14px;background:#ffffff;overflow:hidden;">
                <div style="padding:22px 24px;background:#000641;color:#ffffff;text-align:center;">
                    <div style="font-size:20px;font-weight:800;letter-spacing:1px;">COMPETENCE ACADEMY</div>
                </div>
                <div style="padding:24px;">
                    <p style="margin:0 0 14px;">${escapeHtml(greeting)}</p>
                    <p style="margin:0 0 20px;line-height:1.6;">${escapeHtml(message)}</p>
                    <div style="margin:0 0 22px;padding:16px;border:1px solid #dbeafe;border-radius:10px;background:#eff6ff;text-align:center;">
                        <div style="margin-bottom:7px;color:#64748b;font-size:12px;text-transform:uppercase;letter-spacing:1px;">Votre code</div>
                        <div style="color:#000641;font-size:24px;font-weight:800;letter-spacing:2px;overflow-wrap:anywhere;">${escapeHtml(code)}</div>
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

// Middleware
app.use(helmet());
app.post('/api/tranzak-webhook', express.raw({ type: 'application/json', limit: '1mb' }), async (req, res) => {
    const signature = req.get('x-tranzak-signature') || '';
    const webhookSecret = process.env.TRANZAK_WEBHOOK_SECRET;
    if (!webhookSecret) {
        return res.status(503).json({ status: 'ERROR', message: 'La configuration du webhook Tranzak est incomplète.' });
    }
    if (!Buffer.isBuffer(req.body) || !/^[a-f\d]{64}$/i.test(signature)) {
        return res.status(401).json({ status: 'ERROR', message: 'Signature Tranzak manquante ou invalide.' });
    }

    const expectedSignature = crypto
        .createHmac('sha256', webhookSecret)
        .update(req.body)
        .digest();
    const receivedSignature = Buffer.from(signature, 'hex');
    if (receivedSignature.length !== expectedSignature.length
        || !crypto.timingSafeEqual(receivedSignature, expectedSignature)) {
        return res.status(401).json({ status: 'ERROR', message: 'Signature Tranzak invalide.' });
    }

    let event;
    try {
        event = JSON.parse(req.body.toString('utf8'));
    } catch (error) {
        return res.status(400).json({ status: 'ERROR', message: 'Le contenu du webhook Tranzak est invalide.' });
    }
    const eventName = String(event.event || '').toLowerCase();
    const paymentStatus = String(event.data?.status || '').toLowerCase();
    if (!['payment.success', 'payment.failed'].includes(eventName)) {
        return res.status(200).json({ status: 'SUCCESS', ignored: true });
    }

    try {
        const transactionId = String(event.data?.transaction_id || '').trim();
        const reference = String(event.data?.reference || '').trim();
        if (!transactionId || transactionId.length > 128 || !reference || reference.length > 128) {
            return res.status(400).json({ status: 'ERROR', message: 'Les références du paiement Tranzak sont invalides.' });
        }

        const payment = await CoursePayment.findOne({
            provider: 'tranzak',
            mchTransactionRef: reference
        });
        if (!payment) {
            return res.status(404).json({ status: 'ERROR', message: 'Paiement Tranzak introuvable.' });
        }
        if (payment.requestId && payment.requestId !== transactionId) {
            console.error('Rejected Tranzak webhook with mismatched transaction ID:', reference);
            return res.status(400).json({ status: 'ERROR', message: 'Les informations du paiement Tranzak ne correspondent pas.' });
        }

        if (eventName === 'payment.failed' || paymentStatus === 'failed') {
            await CoursePayment.updateOne(
                { _id: payment._id, status: 'PENDING' },
                { $set: { requestId: transactionId, status: 'REJECTED' } }
            );
            return res.status(200).json({ status: 'SUCCESS' });
        }
        if (eventName !== 'payment.success' || paymentStatus !== 'completed') {
            return res.status(200).json({ status: 'SUCCESS', ignored: true });
        }
        const eventAmount = Number(event.data?.amount);
        if (!Number.isFinite(eventAmount)
            || eventAmount !== payment.amount
            || String(event.data?.currency || '').toUpperCase() !== payment.currencyCode) {
            console.error('Rejected Tranzak webhook with mismatched amount or currency:', reference);
            return res.status(400).json({ status: 'ERROR', message: 'Le montant ou la devise du paiement ne correspond pas.' });
        }
        if (payment.status === 'SUCCESSFUL' && payment.accessGrantedAt) {
            return res.status(200).json({ status: 'SUCCESS', duplicate: true });
        }

        const user = await User.findById(payment.userId).select('_id name email');
        if (!user) throw new Error('Successful Tranzak payment references a missing student account.');

        payment.status = 'SUCCESSFUL';
        payment.requestId = transactionId;
        payment.paidAt = payment.paidAt || new Date();
        await payment.save();

        let access = await CourseEnrollmentAccess.findOne({
            userId: user._id,
            courseId: payment.courseId
        }).select('+encryptedCode');
        if (!access?.encryptedCode) {
            await issueCourseAccessCode(user, payment.courseId, { paymentConfirmed: true });
            access = await CourseEnrollmentAccess.findOne({
                userId: user._id,
                courseId: payment.courseId
            }).select('+encryptedCode');
        }
        if (!access?.encryptedCode) throw new Error('Course access code was not stored after successful Tranzak payment.');

        payment.accessGrantedAt = payment.accessGrantedAt || new Date();
        await payment.save();
        await sendCoursePaymentReceipt(payment);
        return res.status(200).json({ status: 'SUCCESS' });
    } catch (error) {
        console.error('Process Tranzak webhook error:', error);
        return res.status(500).json({ status: 'ERROR', message: 'Le paiement Tranzak n’a pas encore pu être traité.' });
    }
});
app.use(express.json({ limit: '1mb' }));
app.get('/api/ping', (req, res) => {
    res.json({ status: 'ok', uptime: process.uptime() });
});
app.use(cookieParser());
app.use(cors({
    origin: (origin, callback) => {
        if (isAllowedOrigin(origin)) {
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
    windowMs: LOGIN_LOCKOUT_MS,
    max: LOGIN_MAX_FAILED_ATTEMPTS,
    skipSuccessfulRequests: true,
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, message: 'Trop de tentatives. Réessayez dans 10 minutes.' }
});
const signupLimiter = rateLimit({
    windowMs: 10 * 60 * 1000,
    max: SIGNUP_MAX_FAILED_ATTEMPTS,
    skipSuccessfulRequests: true,
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, message: 'Trop de tentatives d’inscription. Réessayez dans 10 minutes.' }
});
const loginLimiter = rateLimit({
    windowMs: LOGIN_LOCKOUT_MS,
    max: LOGIN_MAX_FAILED_ATTEMPTS,
    skipSuccessfulRequests: true,
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, message: 'Trop de tentatives de connexion. Réessayez dans 10 minutes. Si vous avez oublié votre mot de passe, utilisez « Mot de passe oublié ».' }
});
const resetRequestLimiter = rateLimit({
    windowMs: PASSWORD_RESET_LOCKOUT_MS,
    max: PASSWORD_RESET_MAX_ATTEMPTS,
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, message: 'Trop de demandes de récupération. Réessayez dans 10 minutes.' }
});
const resetVerificationLimiter = rateLimit({
    windowMs: PASSWORD_RESET_LOCKOUT_MS,
    max: PASSWORD_RESET_MAX_ATTEMPTS,
    skipSuccessfulRequests: true,
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, message: 'Trop de codes incorrects. Réessayez dans 10 minutes.' }
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
const COURSE_PRICE_DEFAULT_AMOUNT = 5000;
const COURSE_PAYMENT_CURRENCY = 'HTG';
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
    avatarUrl: { type: String, default: '', trim: true, maxlength: 2048 },
    password: { type: String, default: '' },
    loginFailedAttempts: { type: Number, default: 0 },
    loginBlockedUntil: { type: Date, default: null },
    googleId: { type: String, default: '' },
    tokenVersion: { type: Number, default: 0 },
    activeSessionId: { type: String, default: null },
    activeSessionExpiresAt: { type: Date, default: null },
    activeSessionTokenExpiresAt: { type: Date, default: null },
    isLoggedIn: { type: Boolean, default: false },
    nameOnCertificate: { type: String, default: '', trim: true, maxlength: 100 },
    phone: { type: String, default: '', trim: true, maxlength: 30 },
    location: { type: String, default: '', trim: true, maxlength: 100 },
    registeredCourse: { type: String, default: '', enum: ['', ...COURSE_ACCESS_CATEGORIES] },
    accessApprovedAt: { type: Date, default: null }
}, { timestamps: true });

const resetCodeSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true, index: true },
    codeHash: { type: String, required: true },
    attempts: { type: Number, default: 0 },
    blockedUntil: { type: Date, default: null },
    lastSentAt: { type: Date, default: null },
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
const coursePriceSchema = new mongoose.Schema({
    courseId: { type: String, required: true, unique: true, enum: COURSE_ACCESS_CATEGORIES },
    amount: { type: Number, required: true, min: 1, max: 100000000 },
    currencyCode: { type: String, required: true, enum: [COURSE_PAYMENT_CURRENCY], default: COURSE_PAYMENT_CURRENCY }
}, { timestamps: true });
const coursePaymentSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    courseId: { type: String, required: true, enum: COURSE_ACCESS_CATEGORIES, index: true },
    provider: { type: String, enum: ['tranzak', 'stripe', 'moncash', 'natcash'], default: 'tranzak', index: true },
    paymentMethod: { type: String, enum: ['moncash', 'natcash', 'card'], default: 'moncash' },
    amount: { type: Number, required: true, min: 1 },
    currencyCode: { type: String, required: true, enum: [COURSE_PAYMENT_CURRENCY] },
    mchTransactionRef: { type: String, required: true, unique: true, index: true },
    requestId: { type: String, default: '', index: true },
    status: {
        type: String,
        enum: ['PENDING', 'SUCCESSFUL', 'CANCELLED', 'REJECTED'],
        default: 'PENDING',
        index: true
    },
    accessGrantedAt: { type: Date, default: null },
    paidAt: { type: Date, default: null },
    receiptEmailSentAt: { type: Date, default: null },
    receiptEmailClaimedAt: { type: Date, default: null }
}, { timestamps: true });
const accessConfirmationSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true, index: true },
    challengeId: { type: String, required: true, unique: true },
    codeHash: { type: String, required: true },
    attempts: { type: Number, default: 0 },
    blockedUntil: { type: Date, default: null },
    lastSentAt: { type: Date, default: null },
    expiresAt: { type: Date, required: true, index: { expires: 0 } }
}, { timestamps: true });
const User = mongoose.model('User', userSchema);
const ResetCode = mongoose.model('ResetCode', resetCodeSchema);
const CourseProgress = mongoose.model('CourseProgress', courseProgressSchema);
const VideoWatchSession = mongoose.model('VideoWatchSession', videoWatchSessionSchema);
const CourseEnrollmentAccess = mongoose.model('CourseEnrollmentAccess', courseAccessCodeSchema);
const CoursePrice = mongoose.model('CoursePrice', coursePriceSchema);
const CoursePayment = mongoose.model('CoursePayment', coursePaymentSchema);
const AccessConfirmation = mongoose.model('AccessConfirmation', accessConfirmationSchema);
const studentResultSchema = new mongoose.Schema({
    accessCodeHash: { type: String, required: true, unique: true, index: true },
    name: { type: String, required: true, trim: true, maxlength: 100 },
    email: { type: String, required: true, lowercase: true, trim: true, index: true },
    phone: { type: String, required: true, trim: true, maxlength: 30 },
    formation: { type: String, required: true, enum: COURSE_ACCESS_CATEGORIES, index: true },
    modules: {
        type: [{
            name: { type: String, required: true, trim: true, maxlength: 100 },
            score: { type: Number, required: true, min: 0, max: 10 }
        }],
        validate: {
            validator: (modules) => Array.isArray(modules) && modules.length > 0,
            message: 'Au moins un module noté est requis.'
        }
    },
    validated: { type: Boolean, default: false, index: true },
    active: { type: Boolean, default: true, index: true },
    createdBy: { type: String, default: 'admin' }
}, { timestamps: true });
const StudentResult = mongoose.model('StudentResult', studentResultSchema);

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

const sendCourseAccessCodeEmail = async (user, courseId, code, paymentConfirmed = false) => {
    const adminCopyEmails = getAdminNotificationEmails().filter((email) => email !== user.email);
    const courseUrl = getFrontendUrl('/Cours%20en%20Ligne.html', {
        'access-code': code,
        course: courseId
    });
    const emailContent = createCodeEmail({
        greeting: `Bonjour ${user.name},`,
        message: paymentConfirmed
            ? `Votre paiement pour la formation « ${COURSE_TITLES[courseId]} » a été confirmé. Voici votre code personnel pour accéder au cours.`
            : `Voici votre code personnel pour accéder à la formation « ${COURSE_TITLES[courseId]} ».`,
        code,
        buttonLabel: 'Ouvrir le cours',
        buttonUrl: courseUrl,
        note: 'Le code est personnel et reste valable tant que votre accès à la formation est actif. Si vous n’êtes pas déjà connecté(e), connectez-vous : le code restera prêt dans le cours.'
    });
    await sendEmail({
        to: user.email,
        ...(adminCopyEmails.length ? { bcc: adminCopyEmails } : {}),
        subject: `${paymentConfirmed ? 'Paiement confirmé — ' : ''}code d’accès ${COURSE_TITLES[courseId]} | Competence Academy`,
        ...emailContent
    });
};

const sendCoursePaymentReceipt = async (payment) => {
    const claimTime = new Date();
    const claim = await CoursePayment.findOneAndUpdate({
        _id: payment._id,
        receiptEmailSentAt: null,
        $or: [
            { receiptEmailClaimedAt: null },
            { receiptEmailClaimedAt: { $exists: false } },
            { receiptEmailClaimedAt: { $lt: new Date(claimTime.getTime() - 5 * 60 * 1000) } }
        ]
    }, {
        $set: { receiptEmailClaimedAt: claimTime }
    }, { new: true     }).select('userId courseId provider paymentMethod amount currencyCode mchTransactionRef requestId paidAt');
    if (!claim) return;

    try {
        const user = await User.findById(claim.userId).select('name email');
        if (!user) throw new Error('Paid course payment references a missing student account.');
        const access = await CourseEnrollmentAccess.findOne({
            userId: claim.userId,
            courseId: claim.courseId
        }).select('+encryptedCode');
        if (!access?.encryptedCode) throw new Error('Paid course payment has no recoverable course access code.');

        const paidAt = claim.paidAt || new Date();
        const formattedDate = new Intl.DateTimeFormat('fr-HT', {
            dateStyle: 'long',
            timeStyle: 'short',
            timeZone: 'America/Port-au-Prince'
        }).format(paidAt);
        const formattedAmount = `${new Intl.NumberFormat('fr-HT').format(claim.amount)} ${claim.currencyCode}`;
        const studentName = escapeHtml(user.name);
        const courseName = escapeHtml(COURSE_TITLES[claim.courseId]);
        const safeDate = escapeHtml(formattedDate);
        const safeAmount = escapeHtml(formattedAmount);
        const accessCode = decryptCourseAccessCode(access.encryptedCode);
        const safeAccessCode = escapeHtml(accessCode);
        const paymentMethodLabel = claim.paymentMethod === 'natcash' ? 'NatCash'
            : claim.paymentMethod === 'card' ? 'Carte bancaire'
                : claim.paymentMethod === 'moncash' ? 'MonCash'
                    : claim.provider.toUpperCase();
        const safeProvider = escapeHtml(paymentMethodLabel);
        const transactionReference = claim.requestId || claim.mchTransactionRef;
        const safeReference = escapeHtml(transactionReference);

        await sendEmail({
            to: user.email,
            subject: `Reçu de paiement — ${COURSE_TITLES[claim.courseId]} | Competence Academy`,
            text: [
                'REÇU DE PAIEMENT — COMPETENCE ACADEMY',
                `Étudiant : ${user.name}`,
                `Date : ${formattedDate}`,
                `Montant : ${formattedAmount}`,
                `Formation : ${COURSE_TITLES[claim.courseId]}`,
                `Mode de paiement : ${paymentMethodLabel}`,
                `Référence de transaction : ${transactionReference}`,
                `Code d’accès : ${accessCode}`,
                'Statut : Paiement confirmé'
            ].join('\n'),
            html: `
                <div style="margin:0;padding:32px 16px;background:#f3f6fb;font-family:Arial,sans-serif;color:#000641">
                    <div style="max-width:560px;margin:0 auto;padding:32px;border:1px solid #dbe3ee;border-radius:16px;background:#fff">
                        <p style="margin:0 0 8px;color:#000641;font-size:13px;font-weight:bold;letter-spacing:2px">COMPETENCE ACADEMY</p>
                        <h1 style="margin:0 0 8px;color:#000641;font-size:24px">Reçu de paiement</h1>
                        <p style="margin:0 0 24px;color:#15803d;font-weight:bold">Paiement confirmé</p>
                        <p style="margin:0 0 18px">Bonjour ${studentName}, voici le récapitulatif de votre paiement.</p>
                        <table style="width:100%;border-collapse:collapse">
                            <tr><td style="padding:12px;border-bottom:1px solid #e2e8f0;color:#64748b">Étudiant</td><td style="padding:12px;border-bottom:1px solid #e2e8f0;text-align:right;font-weight:bold">${studentName}</td></tr>
                            <tr><td style="padding:12px;border-bottom:1px solid #e2e8f0;color:#64748b">Date</td><td style="padding:12px;border-bottom:1px solid #e2e8f0;text-align:right">${safeDate}</td></tr>
                            <tr><td style="padding:12px;border-bottom:1px solid #e2e8f0;color:#64748b">Formation</td><td style="padding:12px;border-bottom:1px solid #e2e8f0;text-align:right;font-weight:bold">${courseName}</td></tr>
                            <tr><td style="padding:12px;border-bottom:1px solid #e2e8f0;color:#64748b">Montant</td><td style="padding:12px;border-bottom:1px solid #e2e8f0;text-align:right;font-weight:bold">${safeAmount}</td></tr>
                            <tr><td style="padding:12px;border-bottom:1px solid #e2e8f0;color:#64748b">Paiement</td><td style="padding:12px;border-bottom:1px solid #e2e8f0;text-align:right">${safeProvider}</td></tr>
                            <tr><td style="padding:12px;border-bottom:1px solid #e2e8f0;color:#64748b">Référence de transaction</td><td style="padding:12px;border-bottom:1px solid #e2e8f0;text-align:right;overflow-wrap:anywhere">${safeReference}</td></tr>
                            <tr><td style="padding:12px;color:#64748b">Code d’accès au cours</td><td style="padding:12px;text-align:right;font-weight:bold;letter-spacing:1px;overflow-wrap:anywhere">${safeAccessCode}</td></tr>
                        </table>
                        <p style="margin:24px 0 0;color:#64748b;font-size:13px">Conservez ce reçu comme preuve de paiement. Merci d’avoir choisi Competence Academy.</p>
                    </div>
                </div>`
        });
        await CoursePayment.updateOne(
            { _id: claim._id, receiptEmailClaimedAt: claimTime },
            { $set: { receiptEmailSentAt: new Date() }, $unset: { receiptEmailClaimedAt: 1 } }
        );
    } catch (error) {
        await CoursePayment.updateOne(
            { _id: claim._id, receiptEmailClaimedAt: claimTime },
            { $unset: { receiptEmailClaimedAt: 1 } }
        );
        throw error;
    }
};

const issueCourseAccessCode = async (user, courseId, { paymentConfirmed = false } = {}) => {
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
        await sendCourseAccessCodeEmail(user, courseId, code, paymentConfirmed);
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

const grantCourseAccess = async (user, courseId, options) => {
    const existingAccess = await CourseEnrollmentAccess.findOne({ userId: user._id, courseId });
    if (existingAccess) return false;
    await issueCourseAccessCode(user, courseId, options);
    return true;
};

const sendAccessConfirmationCode = async (user, code) => {
    await sendEmail({
        to: user.email,
        subject: 'Votre code de confirmation - Competence Academy',
        ...createCodeEmail({
            greeting: `Bonjour ${user.name},`,
            message: 'Utilisez ce code pour confirmer votre connexion à Competence Academy.',
            code,
            buttonLabel: 'Retourner à la connexion',
            buttonUrl: getFrontendUrl('/Login.html'),
            note: 'Ce code est personnel et expire dans 10 minutes. Ne le partagez avec personne.'
        })
    });
};

const createAccessConfirmation = async (user) => {
    const existingChallenge = await AccessConfirmation.findOne({ userId: user._id })
        .select('challengeId blockedUntil expiresAt lastSentAt');
    const now = new Date();
    if (existingChallenge?.blockedUntil && existingChallenge.blockedUntil > now) {
        const error = new Error('Trop de codes incorrects. Réessayez dans 10 minutes et vérifiez votre e-mail.');
        error.code = 'AUTH_CHALLENGE_LOCKED';
        error.retryAfterSeconds = Math.ceil((existingChallenge.blockedUntil.getTime() - now.getTime()) / 1000);
        throw error;
    }
    if (existingChallenge?.challengeId
        && existingChallenge.expiresAt > now
        && existingChallenge.lastSentAt
        && now.getTime() - existingChallenge.lastSentAt.getTime() < ACCESS_CONFIRMATION_RESEND_INTERVAL_MS) {
        return {
            challengeId: existingChallenge.challengeId,
            message: 'Un code a déjà été envoyé récemment. Vérifiez votre e-mail avant de demander un autre code.'
        };
    }

    const code = createResetCode();
    const challengeId = crypto.randomBytes(24).toString('hex');
    const expiresAt = new Date(Date.now() + ACCESS_CONFIRMATION_TTL_MS);
    const lastSentAt = new Date();
    await AccessConfirmation.findOneAndUpdate(
        { userId: user._id },
        { challengeId, codeHash: hashResetCode(code), attempts: 0, blockedUntil: null, lastSentAt, expiresAt },
        { upsert: true, new: true, setDefaultsOnInsert: true }
    );
    try {
        await sendAccessConfirmationCode(user, code);
    } catch (error) {
        await AccessConfirmation.deleteOne({ userId: user._id, challengeId });
        throw error;
    }

    return {
        challengeId,
        message: 'Un code de confirmation vient d’être envoyé à votre adresse e-mail. Saisissez-le dans les 10 minutes.'
    };
};

const sendPasswordResetCode = async (email, code) => {
    await sendEmail({
        to: email,
        subject: 'Code de réinitialisation de votre mot de passe - Competence Academy',
        ...createCodeEmail({
            greeting: 'Bonjour,',
            message: 'Voici votre nouveau code de vérification pour réinitialiser votre mot de passe. Appuyez sur le bouton pour ouvrir le formulaire avec votre adresse e-mail et le code déjà renseignés.',
            code,
            buttonLabel: 'Réinitialiser mon mot de passe',
            buttonUrl: getFrontendUrl('/Login.html', { 'reset-code': code, email }),
            note: 'Le code expire dans 15 minutes. Vous devrez encore choisir un nouveau mot de passe pour terminer la réinitialisation.'
        })
    });
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

const authenticate = async (req, res, next) => {
    const token = req.cookies?.ca_token || req.headers.authorization?.replace(/^Bearer\s+/i, '');

    if (!token) {
        return res.status(401).json({ success: false, message: 'Non authentifié.' });
    }

    let decoded;
    try {
        decoded = jwt.verify(token, JWT_SECRET);
        if (decoded.accessConfirmed !== true) {
            return res.status(401).json({ success: false, message: 'Confirmation de connexion requise.' });
        }
    } catch (error) {
        return res.status(401).json({ success: false, message: 'Session expirée ou invalide.' });
    }

    try {
        const user = await User.findById(decoded.id)
            .select('tokenVersion activeSessionId activeSessionExpiresAt');
        if (!user) {
            return res.status(401).json({ success: false, message: 'Session expirée ou invalide.' });
        }
        if (decoded.tokenVersion !== user.tokenVersion) {
            return res.status(401).json({ success: false, message: 'Session expirée ou invalide.' });
        }
        const now = new Date();
        if (decoded.sessionId !== user.activeSessionId) {
            clearAuthCookie(res);
            return res.status(401).json({ success: false, message: ACTIVE_SESSION_CONFLICT_MESSAGE });
        }
        if (!user.activeSessionExpiresAt || user.activeSessionExpiresAt <= now
            || (user.activeSessionTokenExpiresAt && user.activeSessionTokenExpiresAt <= now)) {
            clearAuthCookie(res);
            return res.status(401).json({ success: false, message: 'Session expirée ou invalide.' });
        }

        const refreshedSessionExpiresAt = new Date(Math.min(
            now.getTime() + SESSION_IDLE_TIMEOUT_MS,
            user.activeSessionTokenExpiresAt
                ? user.activeSessionTokenExpiresAt.getTime()
                : now.getTime() + SESSION_IDLE_TIMEOUT_MS
        ));
        const refreshedSession = await User.findOneAndUpdate({
            _id: user._id,
            tokenVersion: decoded.tokenVersion,
            activeSessionId: decoded.sessionId,
            activeSessionExpiresAt: { $gt: now }
        }, {
            $set: { activeSessionExpiresAt: refreshedSessionExpiresAt }
        }, { new: true }).select('_id');
        if (!refreshedSession) {
            clearAuthCookie(res);
            return res.status(401).json({ success: false, message: 'Session expirée ou invalide.' });
        }
        req.user = decoded;
        return next();
    } catch (error) {
        console.error('Authentication session validation error:', error);
        return res.status(500).json({ success: false, message: 'Impossible de vérifier la session.' });
    }
};

app.post('/api/admin/request-otp', adminOtpRequestLimiter, async (req, res) => {
    const email = sanitizeEmail(req.body?.email);
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !isAllowedAdminEmail(email)) {
        return res.status(403).json({ success: false, message: 'Accès refusé.' });
    }

    const now = Date.now();
    for (const [challengeEmail, challenge] of adminOtpChallenges) {
        if (challenge.expiresAt <= now) adminOtpChallenges.delete(challengeEmail);
    }
    for (const [sentEmail, sentAt] of adminOtpLastSentAt) {
        if (now - sentAt > 15 * 60 * 1000) adminOtpLastSentAt.delete(sentEmail);
    }

    const lastSentAt = adminOtpLastSentAt.get(email) || 0;
    const retryAfterSeconds = Math.ceil((ADMIN_OTP_RESEND_INTERVAL_MS - (now - lastSentAt)) / 1000);
    if (retryAfterSeconds > 0) {
        return res.status(429).json({
            success: false,
            message: 'Un code vient d’être envoyé. Attendez son expiration avant d’en demander un autre.',
            retryAfterSeconds
        });
    }

    const code = String(crypto.randomInt(100000, 1000000));
    const linkToken = crypto.randomBytes(32).toString('hex');
    const expiresAt = now + ADMIN_OTP_TTL_MS;
    const codeHash = crypto.createHmac('sha256', ADMIN_JWT_SECRET)
        .update(`${email}:${code}`)
        .digest();
    const linkHash = crypto.createHmac('sha256', ADMIN_JWT_SECRET)
        .update(`${email}:${linkToken}`)
        .digest();
    adminOtpChallenges.set(email, { codeHash, linkHash, expiresAt, attempts: 0 });
    adminOtpLastSentAt.set(email, now);

    const adminPageUrl = getFrontendUrl('/Gestion%20Acces%20Cours.html', { adminToken: linkToken });
    try {
        await sendEmail({
            to: email,
            subject: 'Votre code temporaire d’administration - Competence Academy',
            text: `Votre code de confirmation est ${code}. Il expire dans 2 minutes.\n\nOuvrir l’administration et valider automatiquement le code : ${adminPageUrl}\n\nSi vous n’êtes pas à l’origine de cette demande, ignorez ce message.`,
            html: `
                <div style="margin:0;padding:32px 16px;background:#f3f6fb;font-family:Arial,sans-serif;color:#000641">
                    <div style="max-width:520px;margin:0 auto;padding:32px;border:1px solid #dbe3ee;border-radius:16px;background:#fff">
                        <p style="margin:0 0 8px;color:#000641;font-size:13px;font-weight:bold;letter-spacing:2px">COMPETENCE ACADEMY</p>
                        <h1 style="margin:0 0 16px;color:#000641;font-size:24px">Confirmation administrateur</h1>
                        <p style="margin:0 0 20px;line-height:1.6">Utilisez le code ci-dessous pour accéder à l’espace d’administration. Il n’est valable que pendant <strong>2 minutes</strong>.</p>
                        <div style="margin:0 0 24px;padding:20px;border:1px solid #dbe3ee;border-radius:12px;background:#f8fafc;text-align:center">
                            <span style="color:#64748b;font-size:12px;letter-spacing:2px">CODE DE CONFIRMATION</span>
                            <div style="margin-top:8px;color:#000641;font-family:monospace;font-size:36px;font-weight:bold;letter-spacing:8px;user-select:all">${code}</div>
                            <p style="margin:12px 0 0;color:#64748b;font-size:12px">Sélectionnez le code pour le copier.</p>
                        </div>
                        <p style="margin:0 0 24px;text-align:center">
                            <a href="${adminPageUrl}" style="display:inline-block;padding:13px 22px;border-radius:8px;background:#000641;color:#fff;font-weight:bold;text-decoration:none">Ouvrir l’administration et valider le code</a>
                        </p>
                        <p style="margin:0;color:#64748b;font-size:12px;line-height:1.5">Si vous n’êtes pas à l’origine de cette demande, ignorez ce message.</p>
                    </div>
                </div>`
        });
    } catch (error) {
        adminOtpChallenges.delete(email);
        console.error('Admin OTP email delivery failed:', error);
        return res.status(503).json({ success: false, message: 'Impossible d’envoyer le code de confirmation. Réessayez plus tard.' });
    }

    return res.json({ success: true, expiresAt });
});

app.post('/api/admin/verify-link', adminOtpVerifyLimiter, (req, res) => {
    const linkToken = String(req.body?.token || '').trim();
    if (!/^[a-f0-9]{64}$/i.test(linkToken)) {
        return res.status(401).json({ success: false, message: 'Lien expiré ou invalide. Demandez un nouveau code.' });
    }

    const now = Date.now();
    let matchedEmail = '';
    let matchedChallenge;
    for (const [email, challenge] of adminOtpChallenges) {
        if (challenge.expiresAt <= now) {
            adminOtpChallenges.delete(email);
            continue;
        }
        if (!challenge.linkHash || challenge.linkHash.length !== 32) continue;
        const emailHash = crypto.createHmac('sha256', ADMIN_JWT_SECRET)
            .update(`${email}:${linkToken}`)
            .digest();
        if (crypto.timingSafeEqual(emailHash, challenge.linkHash)) {
            matchedEmail = email;
            matchedChallenge = challenge;
            break;
        }
    }
    if (!matchedChallenge || !isAllowedAdminEmail(matchedEmail)) {
        return res.status(401).json({ success: false, message: 'Lien expiré ou déjà utilisé. Demandez un nouveau code.' });
    }

    adminOtpChallenges.delete(matchedEmail);
    const token = jwt.sign(
        { email: matchedEmail, role: 'admin', purpose: 'admin-session' },
        ADMIN_JWT_SECRET,
        {
            expiresIn: ADMIN_JWT_EXPIRES_IN,
            issuer: 'competence-academy',
            audience: 'competence-academy-admin'
        }
    );
    return res.json({
        success: true,
        token,
        expiresIn: 60 * 60,
        email: matchedEmail
    });
});

app.post('/api/admin/verify-otp', adminOtpVerifyLimiter, (req, res) => {
    const email = sanitizeEmail(req.body?.email);
    const code = String(req.body?.code || '').trim();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !isAllowedAdminEmail(email)) {
        return res.status(403).json({ success: false, message: 'Accès refusé.' });
    }

    const challenge = adminOtpChallenges.get(email);
    if (!challenge || challenge.expiresAt <= Date.now() || !/^\d{6}$/.test(code)) {
        adminOtpChallenges.delete(email);
        return res.status(401).json({ success: false, message: 'Code expiré ou invalide.' });
    }

    const submittedHash = crypto.createHmac('sha256', ADMIN_JWT_SECRET)
        .update(`${email}:${code}`)
        .digest();
    if (submittedHash.length !== challenge.codeHash.length
        || !crypto.timingSafeEqual(submittedHash, challenge.codeHash)) {
        challenge.attempts += 1;
        if (challenge.attempts >= ADMIN_OTP_MAX_ATTEMPTS) adminOtpChallenges.delete(email);
        return res.status(401).json({ success: false, message: 'Code expiré ou invalide.' });
    }

    adminOtpChallenges.delete(email);
    const token = jwt.sign(
        { email, role: 'admin', purpose: 'admin-session' },
        ADMIN_JWT_SECRET,
        {
            expiresIn: ADMIN_JWT_EXPIRES_IN,
            issuer: 'competence-academy',
            audience: 'competence-academy-admin'
        }
    );
    return res.json({
        success: true,
        token,
        expiresIn: 60 * 60,
        email
    });
});

app.get('/api/admin/session', (req, res) => {
    const authorization = String(req.get('authorization') || '');
    const tokenMatch = authorization.match(/^Bearer\s+(.+)$/i);
    if (!tokenMatch) {
        return res.status(401).json({ success: false, message: 'Session administrateur requise.' });
    }
    try {
        const decoded = jwt.verify(tokenMatch[1], ADMIN_JWT_SECRET, {
            issuer: 'competence-academy',
            audience: 'competence-academy-admin'
        });
        if (decoded.role !== 'admin' || decoded.purpose !== 'admin-session'
            || !isAllowedAdminEmail(decoded.email)) {
            return res.status(401).json({ success: false, message: 'Session administrateur invalide.' });
        }
        return res.json({ success: true, email: sanitizeEmail(decoded.email) });
    } catch (error) {
        if (error.name !== 'JsonWebTokenError' && error.name !== 'TokenExpiredError') {
            console.error('Admin session validation error:', error);
            return res.status(500).json({ success: false, message: 'Impossible de vérifier la session administrateur.' });
        }
        return res.status(401).json({ success: false, message: 'Session administrateur expirée ou invalide.' });
    }
});

const requireCourseAdmin = (req, res, next) => {
    const authorization = String(req.get('authorization') || '');
    const tokenMatch = authorization.match(/^Bearer\s+(.+)$/i);
    if (!tokenMatch) {
        return res.status(401).json({ success: false, message: 'Session administrateur requise.' });
    }
    try {
        const decoded = jwt.verify(tokenMatch[1], ADMIN_JWT_SECRET, {
            issuer: 'competence-academy',
            audience: 'competence-academy-admin'
        });
        if (decoded.role !== 'admin' || decoded.purpose !== 'admin-session'
            || !isAllowedAdminEmail(decoded.email)) {
            return res.status(401).json({ success: false, message: 'Session administrateur invalide.' });
        }
        req.admin = { email: sanitizeEmail(decoded.email) };
        return next();
    } catch (error) {
        if (error.name !== 'JsonWebTokenError' && error.name !== 'TokenExpiredError') {
            console.error('Admin session validation error:', error);
            return res.status(500).json({ success: false, message: 'Impossible de vérifier la session administrateur.' });
        }
        return res.status(401).json({ success: false, message: 'Session administrateur expirée ou invalide.' });
    }
};

app.get('/api/admin/accounts', requireCourseAdmin, async (req, res) => {
    const page = Math.max(1, Number.parseInt(req.query.page, 10) || 1);
    const limit = Math.min(100, Math.max(1, Number.parseInt(req.query.limit, 10) || 50));
    const search = String(req.query.search || '').trim().slice(0, 100);
    const filter = {};
    if (search) {
        const escapedSearch = search.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        filter.$or = [
            { name: { $regex: escapedSearch, $options: 'i' } },
            { email: { $regex: escapedSearch, $options: 'i' } }
        ];
    }

    try {
        const [accountCount, accounts] = await Promise.all([
            User.countDocuments(filter),
            User.find(filter)
                .select('name email registeredCourse isLoggedIn activeSessionExpiresAt activeSessionTokenExpiresAt createdAt')
                .sort({ createdAt: -1, _id: -1 })
                .skip((page - 1) * limit)
                .limit(limit)
                .lean()
        ]);
        const now = Date.now();
        return res.json({
            success: true,
            accountCount,
            page,
            pages: Math.max(1, Math.ceil(accountCount / limit)),
            accounts: accounts.map((account) => ({
                id: String(account._id),
                name: account.name,
                email: account.email,
                registeredCourse: account.registeredCourse,
                createdAt: account.createdAt,
                isLoggedIn: account.isLoggedIn === true
                    && Boolean(account.activeSessionExpiresAt)
                    && account.activeSessionExpiresAt.getTime() > now
                    && (!account.activeSessionTokenExpiresAt || account.activeSessionTokenExpiresAt.getTime() > now)
            }))
        });
    } catch (error) {
        console.error('Admin account list error:', error);
        return res.status(500).json({ success: false, message: 'Impossible de charger la liste des comptes.' });
    }
});

app.post('/api/admin/accounts/:id/disconnect', requireCourseAdmin, async (req, res) => {
    if (!mongoose.isValidObjectId(req.params.id)) {
        return res.status(400).json({ success: false, message: 'Identifiant de compte invalide.' });
    }

    try {
        const user = await User.findByIdAndUpdate(req.params.id, {
            $inc: { tokenVersion: 1 },
            $set: {
                isLoggedIn: false,
                activeSessionId: null,
                activeSessionExpiresAt: null,
                activeSessionTokenExpiresAt: null
            }
        }).select('_id name email');
        if (!user) return res.status(404).json({ success: false, message: 'Compte utilisateur introuvable.' });

        io.in(String(user._id)).disconnectSockets(true);
        return res.json({
            success: true,
            message: 'La session a été fermée. Le compte existe toujours et peut se reconnecter immédiatement.'
        });
    } catch (error) {
        console.error('Admin account disconnect error:', error);
        return res.status(500).json({ success: false, message: 'Impossible de fermer la session de ce compte.' });
    }
});

app.delete('/api/admin/accounts/:id', requireCourseAdmin, async (req, res) => {
    if (!mongoose.isValidObjectId(req.params.id)) {
        return res.status(400).json({ success: false, message: 'Identifiant de compte invalide.' });
    }

    let account;
    let mongoSession;
    try {
        mongoSession = await mongoose.startSession();
        await mongoSession.withTransaction(async () => {
            account = await User.findById(req.params.id)
                .select('_id email')
                .session(mongoSession);
            if (!account) return;

            await ResetCode.deleteMany({ email: account.email }, { session: mongoSession });
            await CourseProgress.deleteMany({ userId: account._id }, { session: mongoSession });
            await VideoWatchSession.deleteMany({ userId: account._id }, { session: mongoSession });
            await CourseEnrollmentAccess.deleteMany({ userId: account._id }, { session: mongoSession });
            await AccessConfirmation.deleteMany({ userId: account._id }, { session: mongoSession });
            await User.deleteOne({ _id: account._id }, { session: mongoSession });
        });
    } catch (error) {
        console.error('Admin account deletion error:', error);
        return res.status(500).json({ success: false, message: 'Impossible de supprimer ce compte. Aucun changement n’a été confirmé.' });
    } finally {
        if (mongoSession) await mongoSession.endSession();
    }

    if (!account) return res.status(404).json({ success: false, message: 'Compte utilisateur introuvable.' });
    io.in(String(account._id)).disconnectSockets(true);
    return res.json({
        success: true,
        message: 'Compte supprimé. Les paiements et les résultats sont conservés ; cette adresse e-mail peut être réinscrite.'
    });
});

const createStudentResultCode = () => `CA-RESULT-${crypto.randomBytes(6).toString('hex').toUpperCase()}`;
const hashStudentResultCode = (code) => crypto.createHmac('sha256', JWT_SECRET)
    .update(`student-result:${String(code).trim().toUpperCase()}`)
    .digest('hex');
const getStudentResultSummary = (result) => {
    const modules = result.modules.map((module) => ({
        nom: module.name,
        note: `${module.score.toFixed(1)}/10`,
        statut: module.score >= 7 ? 'Validé' : 'À renforcer'
    }));
    const average = modules.length
        ? result.modules.reduce((sum, module) => sum + module.score, 0) / result.modules.length
        : 0;
    const progression = Math.round((Math.min(modules.length, 5) / 5) * 100);
    const validated = average >= 7 && result.modules.every((module) => module.score >= 7);
    return {
        id: String(result._id),
        nom: result.name,
        email: result.email,
        telephone: result.phone,
        filiere: COURSE_TITLES[result.formation],
        validated: Boolean(result.validated),
        statut: result.validated ? (validated ? 'Certifié • Terminé' : 'Certifié') : 'En cours',
        progression,
        moyenne: average.toFixed(2),
        mention: average >= 8 ? 'Mention : Excellent' : average >= 7.5 ? 'Mention : Très Bien' : average >= 7 ? 'Mention : Bien' : 'Mention : À renforcer',
        modules
    };
};
const validateStudentResultInput = (body) => {
    const name = String(body?.name || '').trim();
    const email = sanitizeEmail(body?.email);
    const phone = String(body?.phone || '').trim();
    const formation = String(body?.formation || '').trim();
    const submittedModules = body?.modules;
    const errors = [];
    if (!name || name.length > 100) errors.push('Le nom est obligatoire (100 caractères maximum).');
    if (!/^\S+@\S+\.\S+$/.test(email)) errors.push('Une adresse e-mail valide est requise.');
    const phoneDigits = phone.replace(/\D/g, '');
    if (!phone || phone.length > 30 || phoneDigits.length < 7 || phoneDigits.length > 15) {
        errors.push('Un numéro WhatsApp valide est requis (7 à 15 chiffres).');
    }
    if (!COURSE_ACCESS_CATEGORIES.includes(formation)) errors.push('La formation sélectionnée est invalide.');
    if (!Array.isArray(submittedModules) || !submittedModules.length) errors.push('Ajoutez au moins un module avec sa note.');
    const modules = Array.isArray(submittedModules) ? submittedModules.map((module, index) => {
        const moduleName = String(module?.name || '').trim();
        const score = Number(module?.score);
        if (!moduleName || moduleName.length > 100) errors.push(`Le nom du module ${index + 1} est obligatoire (100 caractères maximum).`);
        if (!Number.isFinite(score) || score < 0 || score > 10) errors.push(`La note du module ${index + 1} doit être comprise entre 0 et 10.`);
        return { name: moduleName, score };
    }) : [];
    const uniqueNames = new Set(modules.map((module) => module.name.toLocaleLowerCase()));
    if (uniqueNames.size !== modules.length) errors.push('Chaque module doit avoir un nom différent.');
    return {
        errors,
        document: { name, email, phone, formation, modules, validated: body?.validated === true }
    };
};

app.get('/api/admin/results', requireCourseAdmin, async (req, res) => {
    const page = Math.max(1, Number.parseInt(req.query.page, 10) || 1);
    const limit = Math.min(100, Math.max(1, Number.parseInt(req.query.limit, 10) || 50));
    try {
        const [results, total] = await Promise.all([
            StudentResult.find({ active: true })
                .select('name email phone formation modules validated createdAt')
                .sort({ createdAt: -1 })
                .skip((page - 1) * limit)
                .limit(limit)
                .lean(),
            StudentResult.countDocuments({ active: true })
        ]);
        res.json({
            success: true,
            results: results.map((result) => ({
                ...getStudentResultSummary(result),
                formation: result.formation,
                modulesRaw: result.modules.map((module) => ({ name: module.name, score: module.score }))
            })),
            total,
            page,
            pages: Math.ceil(total / limit)
        });
    } catch (error) {
        console.error('Admin student results list error:', error);
        res.status(500).json({ success: false, message: 'Impossible de charger les résultats des étudiants.' });
    }
});

app.post('/api/admin/results', requireCourseAdmin, async (req, res) => {
    const { errors, document } = validateStudentResultInput(req.body);
    if (errors.length) return res.status(400).json({ success: false, message: errors.join(' ') });

    const code = document.validated ? createStudentResultCode() : '';
    let result;
    try {
        result = await StudentResult.create({
            ...document,
            accessCodeHash: hashStudentResultCode(code || createStudentResultCode())
        });
    } catch (error) {
        console.error('Admin student result creation error:', error);
        res.status(500).json({ success: false, message: 'Impossible d’enregistrer le bulletin.' });
        return;
    }

    if (!document.validated) {
        return res.status(201).json({
            success: true,
            message: 'Bulletin enregistré comme en cours. Validez-le pour générer le code d’accès.',
            result: getStudentResultSummary(result)
        });
    }

    const resultUrl = getFrontendUrl('/resultats.html', { code });
    const whatsAppText = `Bonjour ${document.name}, voici votre code personnel pour consulter votre bulletin Competence Academy : ${code}. Ouvrez le lien ${resultUrl}`;
    res.status(201).json({
        success: true,
        message: 'Bulletin enregistré. Choisissez un mode d’envoi du code d’accès.',
        code,
        result: getStudentResultSummary(result),
        resultUrl,
        whatsAppUrl: `https://wa.me/${document.phone.replace(/\D/g, '')}?text=${encodeURIComponent(whatsAppText)}`
    });
});

app.put('/api/admin/results/:id', requireCourseAdmin, async (req, res) => {
    if (!mongoose.isValidObjectId(req.params.id)) {
        return res.status(400).json({ success: false, message: 'Identifiant de bulletin invalide.' });
    }
    const { errors, document } = validateStudentResultInput(req.body);
    if (errors.length) return res.status(400).json({ success: false, message: errors.join(' ') });
    try {
        const code = document.validated ? createStudentResultCode() : '';
        const result = await StudentResult.findByIdAndUpdate(req.params.id, {
            ...document,
            accessCodeHash: hashStudentResultCode(code || createStudentResultCode())
        }, {
            new: true,
            runValidators: true
        });
        if (!result) return res.status(404).json({ success: false, message: 'Bulletin introuvable.' });
        if (!document.validated) {
            return res.json({
                success: true,
                message: 'Bulletin modifié. Il est en attente de validation et le code précédent a été désactivé.',
                result: getStudentResultSummary(result)
            });
        }
        const resultUrl = getFrontendUrl('/resultats.html', { code });
        const whatsAppText = `Bonjour ${document.name}, voici votre code personnel pour consulter votre bulletin Competence Academy : ${code}. Ouvrez le lien ${resultUrl}`;
        res.json({
            success: true,
            message: 'Bulletin modifié. Choisissez un mode d’envoi du code d’accès.',
            code,
            result: getStudentResultSummary(result),
            resultUrl,
            whatsAppUrl: `https://wa.me/${document.phone.replace(/\D/g, '')}?text=${encodeURIComponent(whatsAppText)}`
        });
    } catch (error) {
        console.error('Admin student result update error:', error);
        res.status(500).json({ success: false, message: 'Impossible de modifier le bulletin.' });
    }
});

app.post('/api/admin/results/:id/send-email', requireCourseAdmin, async (req, res) => {
    if (!mongoose.isValidObjectId(req.params.id)) {
        return res.status(400).json({ success: false, message: 'Identifiant de bulletin invalide.' });
    }
    const code = String(req.body?.code || '').trim().toUpperCase();
    if (!/^CA-RESULT-[A-F0-9]{12}$/.test(code)) {
        return res.status(400).json({ success: false, message: 'Code d’accès au bulletin invalide.' });
    }

    try {
        const result = await StudentResult.findOne({
            _id: req.params.id,
            active: true
        }).select('name email formation validated accessCodeHash');
        if (!result) return res.status(404).json({ success: false, message: 'Bulletin introuvable.' });
        if (!result.validated) {
            return res.status(409).json({ success: false, message: 'Le bulletin doit être validé avant son envoi.' });
        }

        const storedHash = Buffer.from(result.accessCodeHash, 'hex');
        const submittedHash = Buffer.from(hashStudentResultCode(code), 'hex');
        if (storedHash.length !== submittedHash.length || !crypto.timingSafeEqual(storedHash, submittedHash)) {
            return res.status(403).json({ success: false, message: 'Le code d’accès ne correspond plus à ce bulletin.' });
        }

        const resultUrl = getFrontendUrl('/resultats.html', { code });
        await sendEmail({
            to: result.email,
            subject: 'Votre bulletin de résultats — Competence Academy',
            ...createCodeEmail({
                greeting: `Bonjour ${result.name},`,
                message: `Votre bulletin pour la formation ${COURSE_TITLES[result.formation]} est disponible.`,
                code,
                buttonLabel: 'Consulter mon bulletin',
                buttonUrl: resultUrl,
                note: 'Conservez ce code personnel. Il donne accès à votre bulletin et ne doit pas être partagé.'
            })
        });
        return res.json({ success: true, emailSent: true, message: 'Bulletin envoyé par e-mail.' });
    } catch (error) {
        console.error('Admin student result email delivery failed:', error);
        return res.status(503).json({ success: false, message: 'Impossible d’envoyer le bulletin par e-mail. Réessayez plus tard.' });
    }
});

app.delete('/api/admin/results/:id', requireCourseAdmin, async (req, res) => {
    if (!mongoose.isValidObjectId(req.params.id)) {
        return res.status(400).json({ success: false, message: 'Identifiant de bulletin invalide.' });
    }
    try {
        const result = await StudentResult.findByIdAndDelete(req.params.id);
        if (!result) return res.status(404).json({ success: false, message: 'Bulletin introuvable.' });
        res.json({ success: true, message: 'Bulletin et code d’accès supprimés.' });
    } catch (error) {
        console.error('Admin student result delete error:', error);
        res.status(500).json({ success: false, message: 'Impossible de supprimer le bulletin.' });
    }
});

app.post('/api/results/verify', async (req, res) => {
    const code = String(req.body?.code || '').trim();
    if (!/^CA-RESULT-[A-F0-9]{12}$/i.test(code)) {
        return res.status(400).json({ success: false, message: 'Vérifiez le format du code de votre bulletin.' });
    }
    try {
        const result = await StudentResult.findOne({
            accessCodeHash: hashStudentResultCode(code),
            active: true
        }).select('name email phone formation modules validated createdAt');
        if (!result) return res.status(404).json({ success: false, message: 'Code invalide ou bulletin indisponible.' });
        if (!result.validated) return res.status(403).json({ success: false, message: 'Ce bulletin est en attente de validation.' });
        const summary = getStudentResultSummary(result);
        res.json({
            success: true,
            result: {
                nom: summary.nom,
                filiere: summary.filiere,
                validated: summary.validated,
                statut: summary.statut,
                progression: summary.progression,
                moyenne: summary.moyenne,
                mention: summary.mention,
                modules: summary.modules
            }
        });
    } catch (error) {
        console.error('Student result verification error:', error);
        res.status(500).json({ success: false, message: 'Impossible de charger le bulletin. Réessayez plus tard.' });
    }
});

// 1. Route d’inscription
const getRegistrationStatusPayload = () => ({
    success: true,
    open: true,
    registrationOpen: true,
    message: 'Les inscriptions sont actuellement ouvertes.'
});

app.get('/api/signup/status', async (req, res) => {
    try {
        return res.json(getRegistrationStatusPayload());
    } catch (error) {
        console.error('Signup status check error:', error);
        return res.status(200).json(getRegistrationStatusPayload());
    }
});
app.get('/api/inscription-status', async (req, res) => {
    try {
        return res.json(getRegistrationStatusPayload());
    } catch (error) {
        console.error('Inscription status check error:', error);
        return res.status(200).json(getRegistrationStatusPayload());
    }
});

app.post('/api/signup', signupLimiter, async (req, res) => {
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
        if (error.code === 'AUTH_CHALLENGE_LOCKED') {
            res.set('Retry-After', String(error.retryAfterSeconds));
            return res.status(429).json({
                success: false,
                message: 'Trop de codes incorrects. Réessayez dans 10 minutes et vérifiez votre e-mail.',
                retryAfterSeconds: error.retryAfterSeconds
            });
        }
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
app.post('/api/login', loginLimiter, async (req, res) => {
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

        const now = new Date();
        if (user.loginBlockedUntil && user.loginBlockedUntil > now) {
            const retryAfterSeconds = Math.ceil((user.loginBlockedUntil.getTime() - now.getTime()) / 1000);
            res.set('Retry-After', String(retryAfterSeconds));
            return res.status(429).json({
                success: false,
                message: 'Trop de mots de passe incorrects. Réessayez dans 10 minutes. Si vous avez oublié votre mot de passe, utilisez « Mot de passe oublié ».'
            });
        }
        if (user.loginBlockedUntil && user.loginBlockedUntil <= now) {
            await User.updateOne(
                { _id: user._id, loginBlockedUntil: { $lte: now } },
                { $set: { loginFailedAttempts: 0, loginBlockedUntil: null } }
            );
            user.loginFailedAttempts = 0;
            user.loginBlockedUntil = null;
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            const failedLogin = await User.findOneAndUpdate(
                { _id: user._id },
                { $inc: { loginFailedAttempts: 1 } },
                { new: true }
            ).select('loginFailedAttempts');
            if (failedLogin && failedLogin.loginFailedAttempts >= LOGIN_MAX_FAILED_ATTEMPTS) {
                const blockedUntil = new Date(Date.now() + LOGIN_LOCKOUT_MS);
                await User.updateOne(
                    { _id: user._id },
                    { $set: { loginBlockedUntil: blockedUntil } }
                );
                res.set('Retry-After', String(Math.ceil(LOGIN_LOCKOUT_MS / 1000)));
                return res.status(429).json({
                    success: false,
                    message: 'Trop de mots de passe incorrects. Réessayez dans 10 minutes. Si vous avez oublié votre mot de passe, utilisez « Mot de passe oublié ».'
                });
            }
            return res.status(400).json({ success: false, message: 'Adresse e-mail ou mot de passe incorrect.' });
        }

        if (user.loginFailedAttempts || user.loginBlockedUntil) {
            await User.updateOne(
                { _id: user._id },
                { $set: { loginFailedAttempts: 0, loginBlockedUntil: null } }
            );
        }

        if (await hasActiveSession(user._id)) {
            return res.status(401).json({ success: false, message: ACTIVE_SESSION_CONFLICT_MESSAGE });
        }

        if (user.accessApprovedAt) {
            return await sendAuthenticatedSession(res, user);
        }

        const confirmation = await createAccessConfirmation(user);

        res.json({
            success: true,
            ...confirmation
        });
    } catch (error) {
        console.error('Login error:', error);
        if (error.code === 'AUTH_CHALLENGE_LOCKED') {
            res.set('Retry-After', String(error.retryAfterSeconds));
            return res.status(429).json({
                success: false,
                message: 'Trop de codes incorrects. Réessayez dans 10 minutes et vérifiez votre e-mail.',
                retryAfterSeconds: error.retryAfterSeconds
            });
        }
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

        const googleAvatarUrl = /^https:\/\//i.test(String(payload?.picture || ''))
            ? String(payload.picture).slice(0, 2048)
            : '';
        if (!user) {
            user = await User.create({ name, email, googleId, avatarUrl: googleAvatarUrl });
        } else {
            let profileChanged = false;
            if (!user.googleId) {
                user.googleId = googleId;
                profileChanged = true;
            }
            if (googleAvatarUrl && user.avatarUrl !== googleAvatarUrl) {
                user.avatarUrl = googleAvatarUrl;
                profileChanged = true;
            }
            if (profileChanged) await user.save();
        }

        if (await hasActiveSession(user._id)) {
            return res.status(401).json({ success: false, message: ACTIVE_SESSION_CONFLICT_MESSAGE });
        }

        if (user.accessApprovedAt) {
            return await sendAuthenticatedSession(res, user);
        }

        const confirmation = await createAccessConfirmation(user);

        res.json({
            success: true,
            ...confirmation
        });

    } catch (error) {
        console.error(error);
        if (error.code === 'AUTH_CHALLENGE_LOCKED') {
            res.set('Retry-After', String(error.retryAfterSeconds));
            return res.status(429).json({
                success: false,
                message: 'Trop de codes incorrects. Réessayez dans 10 minutes et vérifiez votre e-mail.',
                retryAfterSeconds: error.retryAfterSeconds
            });
        }
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
        if (!challenge || challenge.expiresAt <= new Date()) {
            if (challenge) await AccessConfirmation.deleteOne({ _id: challenge._id });
            return res.status(400).json({ success: false, message: 'Code de confirmation invalide ou expiré.' });
        }
        if (challenge.blockedUntil && challenge.blockedUntil > new Date()) {
            const retryAfterSeconds = Math.ceil((challenge.blockedUntil.getTime() - Date.now()) / 1000);
            res.set('Retry-After', String(retryAfterSeconds));
            return res.status(429).json({
                success: false,
                message: 'Trop de codes incorrects. Réessayez dans 10 minutes et vérifiez votre e-mail.',
                retryAfterSeconds
            });
        }

        const submittedHash = Buffer.from(hashResetCode(code), 'hex');
        const expectedHash = Buffer.from(challenge.codeHash, 'hex');
        const isCorrectCode = submittedHash.length === expectedHash.length
            && crypto.timingSafeEqual(submittedHash, expectedHash);
        if (!isCorrectCode) {
            const now = new Date();
            const failedAttempt = await AccessConfirmation.findOneAndUpdate(
                {
                    _id: challenge._id,
                    codeHash: challenge.codeHash,
                    attempts: { $lt: ACCESS_CONFIRMATION_MAX_ATTEMPTS },
                    $or: [{ blockedUntil: null }, { blockedUntil: { $lte: now } }]
                },
                { $inc: { attempts: 1 } },
                { new: true }
            ).select('attempts');
            const currentChallenge = failedAttempt || await AccessConfirmation.findById(challenge._id)
                .select('attempts blockedUntil');
            if (!currentChallenge) {
                return res.status(400).json({ success: false, message: 'Code de confirmation invalide ou expiré.' });
            }
            if (currentChallenge.blockedUntil && currentChallenge.blockedUntil > now) {
                const retryAfterSeconds = Math.ceil((currentChallenge.blockedUntil.getTime() - now.getTime()) / 1000);
                res.set('Retry-After', String(retryAfterSeconds));
                return res.status(429).json({
                    success: false,
                    message: 'Trop de codes incorrects. Réessayez dans 10 minutes et vérifiez votre e-mail.',
                    retryAfterSeconds
                });
            }
            if (currentChallenge.attempts >= ACCESS_CONFIRMATION_MAX_ATTEMPTS) {
                const user = await User.findById(challenge.userId).select('name email');
                if (!user) {
                    await challenge.deleteOne();
                    return res.status(400).json({ success: false, message: 'Code de confirmation invalide ou expiré.' });
                }

                const replacementCode = createResetCode();
                const blockedUntil = new Date(Date.now() + ACCESS_CONFIRMATION_LOCKOUT_MS);
                const replacementChallenge = await AccessConfirmation.findOneAndUpdate(
                    {
                        _id: challenge._id,
                        codeHash: challenge.codeHash,
                        attempts: { $gte: ACCESS_CONFIRMATION_MAX_ATTEMPTS },
                        $or: [{ blockedUntil: null }, { blockedUntil: { $lte: now } }]
                    },
                    {
                        $set: {
                            codeHash: hashResetCode(replacementCode),
                            attempts: 0,
                            blockedUntil,
                            expiresAt: new Date(Date.now() + ACCESS_CONFIRMATION_TTL_MS),
                            lastSentAt: new Date()
                        }
                    },
                    { new: true }
                );
                if (!replacementChallenge) {
                    const latestChallenge = await AccessConfirmation.findById(challenge._id)
                        .select('blockedUntil');
                    const retryAfterSeconds = latestChallenge?.blockedUntil
                        ? Math.max(1, Math.ceil((latestChallenge.blockedUntil.getTime() - Date.now()) / 1000))
                        : ACCESS_CONFIRMATION_LOCKOUT_MS / 1000;
                    res.set('Retry-After', String(retryAfterSeconds));
                    return res.status(429).json({
                        success: false,
                        message: 'Trop de demandes de code. Réessayez dans 10 minutes et vérifiez votre e-mail.',
                        retryAfterSeconds
                    });
                }
                try {
                    await sendAccessConfirmationCode(user, replacementCode);
                } catch (error) {
                    console.error('Replacement access confirmation email failed:', error);
                    res.set('Retry-After', String(ACCESS_CONFIRMATION_LOCKOUT_MS / 1000));
                    return res.status(503).json({
                        success: false,
                        message: 'Trop de codes incorrects. Réessayez dans 10 minutes. Le nouvel e-mail n’a pas pu être envoyé; veuillez demander un nouveau code après ce délai.'
                    });
                }

                res.set('Retry-After', String(ACCESS_CONFIRMATION_LOCKOUT_MS / 1000));
                return res.status(429).json({
                    success: false,
                    message: 'Un nouveau code a été envoyé à votre adresse e-mail. Réessayez dans 10 minutes.',
                    retryAfterSeconds: ACCESS_CONFIRMATION_LOCKOUT_MS / 1000
                });
            }
            return res.status(400).json({ success: false, message: 'Code de confirmation invalide ou expiré.' });
        }

        const user = await User.findById(challenge.userId)
            .select('_id name email nameOnCertificate phone location registeredCourse accessApprovedAt');
        await AccessConfirmation.deleteOne({ _id: challenge._id });
        if (!user) {
            return res.status(404).json({ success: false, message: 'Compte utilisateur introuvable.' });
        }

        if (await hasActiveSession(user._id)) {
            return res.status(401).json({ success: false, message: ACTIVE_SESSION_CONFLICT_MESSAGE });
        }

        if (!user.accessApprovedAt) {
            user.accessApprovedAt = new Date();
            await user.save();
        }
        await sendAuthenticatedSession(res, user);
    } catch (error) {
        console.error('Confirm login access error:', error);
        res.status(500).json({ success: false, message: 'Impossible de confirmer cette connexion.' });
    }
});

const accessConfirmationRateLimiters = new Map();
const getAccessConfirmationRateLimitState = (key) => {
    const current = accessConfirmationRateLimiters.get(key);
    if (!current) return null;
    if (Date.now() >= current.blockedUntil) {
        accessConfirmationRateLimiters.delete(key);
        return null;
    }
    return current;
};

const registerAccessConfirmationAttempt = (key) => {
    const now = Date.now();
    const current = accessConfirmationRateLimiters.get(key) || { attempts: 0, blockedUntil: 0, lastRequestAt: 0 };
    const windowStart = now - (15 * 60 * 1000);
    if (current.blockedUntil > now) {
        return { blocked: true, retryAfterMs: current.blockedUntil - now };
    }
    if (current.lastRequestAt < windowStart) {
        current.attempts = 0;
    }
    current.lastRequestAt = now;
    current.attempts += 1;
    if (current.attempts > ACCESS_CONFIRMATION_MAX_REQUESTS) {
        current.blockedUntil = now + ACCESS_CONFIRMATION_REQUEST_LOCKOUT_MS;
        current.attempts = ACCESS_CONFIRMATION_MAX_REQUESTS + 1;
        accessConfirmationRateLimiters.set(key, current);
        return { blocked: true, retryAfterMs: ACCESS_CONFIRMATION_REQUEST_LOCKOUT_MS };
    }
    accessConfirmationRateLimiters.set(key, current);
    return { blocked: false, retryAfterMs: 0 };
};

const getAccessConfirmationRateLimitKey = (req) => {
    const ip = String(req.ip || req.headers['x-forwarded-for'] || 'unknown').trim();
    const email = sanitizeEmail(req.body?.email || req.body?.userEmail || '');
    return email ? `email:${email}` : `ip:${ip}`;
};

app.post('/api/auth/request-access-code', async (req, res) => {
    try {
        const email = sanitizeEmail(req.body?.email);
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            return res.status(400).json({ success: false, message: 'Adresse e-mail invalide.' });
        }
        const key = getAccessConfirmationRateLimitKey(req);
        const rateState = getAccessConfirmationRateLimitState(key);
        if (rateState && rateState.blockedUntil > Date.now()) {
            return res.status(429).json({
                success: false,
                message: 'Trop de tentatives. Réessayez dans 15 minutes.',
                retryAfterSeconds: Math.ceil((rateState.blockedUntil - Date.now()) / 1000)
            });
        }
        const user = await User.findOne({ email }).select('_id name email');
        if (!user) {
            return res.status(404).json({ success: false, message: 'Aucun compte trouvé pour cette adresse e-mail.' });
        }
        const activeChallenge = await AccessConfirmation.findOne({ userId: user._id })
            .select('blockedUntil lastSentAt');
        if (activeChallenge?.blockedUntil && activeChallenge.blockedUntil > new Date()) {
            const retryAfterSeconds = Math.ceil((activeChallenge.blockedUntil.getTime() - Date.now()) / 1000);
            res.set('Retry-After', String(retryAfterSeconds));
            return res.status(429).json({
                success: false,
                message: 'Un nouveau code a été envoyé à votre adresse e-mail. Réessayez dans 10 minutes.',
                retryAfterSeconds
            });
        }
        if (activeChallenge?.lastSentAt
            && Date.now() - activeChallenge.lastSentAt.getTime() < ACCESS_CONFIRMATION_RESEND_INTERVAL_MS) {
            return res.json({
                success: true,
                message: 'Un code a déjà été envoyé récemment. Vérifiez votre e-mail avant de demander un autre code.'
            });
        }
        const attempt = registerAccessConfirmationAttempt(key);
        if (attempt.blocked) {
            return res.status(429).json({
                success: false,
                message: 'Trop de demandes de code. Réessayez dans 15 minutes.',
                retryAfterSeconds: Math.ceil(attempt.retryAfterMs / 1000)
            });
        }
        const confirmation = await createAccessConfirmation(user);
        return res.json({ success: true, ...confirmation });
    } catch (error) {
        console.error('Request access confirmation error:', error);
        if (error.code === 'AUTH_CHALLENGE_LOCKED') {
            res.set('Retry-After', String(error.retryAfterSeconds));
            return res.status(429).json({
                success: false,
                message: 'Trop de codes incorrects. Réessayez dans 10 minutes et vérifiez votre e-mail.',
                retryAfterSeconds: error.retryAfterSeconds
            });
        }
        return res.status(500).json({ success: false, message: 'Impossible d’envoyer le code de confirmation.' });
    }
});

app.post('/api/contact', async (req, res) => {
    const name = String(req.body?.name || '').trim();
    const email = sanitizeEmail(req.body?.email);
    const message = String(req.body?.message || '').trim();
    if (!name || name.length > 100 || !email || email.length > 254
        || !/^\S+@\S+\.\S+$/.test(email) || !message || message.length > 5000) {
        return res.status(400).json({ success: false, message: 'Veuillez vérifier les champs du formulaire.' });
    }

    try {
        await sendEmail({
            to: getAdminNotificationEmails(),
            subject: 'Nouveau message de contact | Competence Academy',
            text: `Nouveau message depuis le formulaire de contact\n\nNom : ${name}\nEmail : ${email}\n\nMessage :\n${message}\n\nCompetence Academy — Formation pratique et professionnelle`,
            html: `
                <div style="margin:0;background:#f3f6fb;padding:28px 12px;font-family:Arial,sans-serif;color:#000641;">
                    <div style="max-width:600px;margin:0 auto;border:1px solid #dbe3ee;border-radius:14px;background:#ffffff;overflow:hidden;">
                        <div style="height:5px;background:#f76b00;"></div>
                        <div style="padding:22px 24px;background:#000641;color:#ffffff;text-align:center;">
                            <div style="font-size:20px;font-weight:800;letter-spacing:1px;">COMPETENCE ACADEMY</div>
                            <div style="margin-top:6px;color:#dbe4f0;font-size:13px;">Nouveau message depuis le formulaire de contact</div>
                        </div>
                        <div style="padding:24px;">
                            <table role="presentation" border="0" cellpadding="0" cellspacing="0" style="width:100%;border-collapse:collapse;">
                                <tr>
                                    <td style="padding:0 0 14px;color:#64748b;font-size:12px;font-weight:700;letter-spacing:.6px;text-transform:uppercase;">Nom</td>
                                </tr>
                                <tr>
                                    <td style="padding:0 0 20px;color:#1e293b;font-size:15px;line-height:1.5;">${escapeHtml(name)}</td>
                                </tr>
                                <tr>
                                    <td style="padding:0 0 14px;color:#64748b;font-size:12px;font-weight:700;letter-spacing:.6px;text-transform:uppercase;">Adresse e-mail</td>
                                </tr>
                                <tr>
                                    <td style="padding:0 0 20px;font-size:15px;line-height:1.5;"><a href="mailto:${escapeHtml(email)}" style="color:#000641;text-decoration:underline;">${escapeHtml(email)}</a></td>
                                </tr>
                            </table>
                            <div style="padding:16px;border:1px solid #dbe3ee;border-left:4px solid #f76b00;border-radius:10px;background:#f8fafc;">
                                <div style="margin-bottom:10px;color:#64748b;font-size:12px;font-weight:700;letter-spacing:.6px;text-transform:uppercase;">Message</div>
                                <div style="color:#334155;font-size:15px;line-height:1.7;white-space:pre-wrap;overflow-wrap:anywhere;">${escapeHtml(message)}</div>
                            </div>
                        </div>
                        <div style="padding:14px 20px;border-top:1px solid #e2e8f0;color:#64748b;font-size:12px;text-align:center;">Competence Academy — Formation pratique et professionnelle</div>
                    </div>
                </div>
            `
        });
        return res.json({ success: true, message: 'Message envoyé avec succès !' });
    } catch (error) {
        console.error('Contact form email error:', error);
        const status = error.code === 'EMAIL_DELIVERY_FAILED' ? 503 : 500;
        return res.status(status).json({
            success: false,
            message: 'Impossible d’envoyer votre message pour le moment. Veuillez réessayer plus tard.'
        });
    }
});

// 4. Route de demande d’un code de récupération (envoi du code à 6 chiffres)
app.post('/api/forgot-password', resetRequestLimiter, async (req, res) => {
    const email = sanitizeEmail(req.body?.email);
    const genericResponseMessage = 'Si le compte existe et qu’aucun délai de sécurité n’est actif, un code de vérification sera envoyé.';

    if (!email || !/^\S+@\S+\.\S+$/.test(email)) {
        return res.status(400).json({ success: false, message: 'Veuillez fournir un email valide.' });
    }

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.json({ success: true, message: genericResponseMessage });
        }

        const existingResetCode = await ResetCode.findOne({ email }).select('blockedUntil lastSentAt');
        const now = new Date();
        if (existingResetCode?.blockedUntil && existingResetCode.blockedUntil > now) {
            return res.json({ success: true, message: genericResponseMessage });
        }
        if (existingResetCode?.lastSentAt
            && now.getTime() - existingResetCode.lastSentAt.getTime() < ACCESS_CONFIRMATION_RESEND_INTERVAL_MS) {
            return res.json({ success: true, message: genericResponseMessage });
        }

        const resetCode = createResetCode();
        const lastSentAt = new Date();
        await ResetCode.findOneAndUpdate(
            { email },
            {
                email,
                codeHash: hashResetCode(resetCode),
                attempts: 0,
                blockedUntil: null,
                lastSentAt,
                expiresAt: new Date(Date.now() + PASSWORD_RESET_CODE_TTL_MS)
            },
            { upsert: true, new: true }
        );

        await sendPasswordResetCode(email, resetCode);
        return res.json({ success: true, message: genericResponseMessage });

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
        if (!/^\d{6}$/.test(code)) {
            return res.status(400).json({ success: false, message: 'Le code doit contenir exactement 6 chiffres.' });
        }

        if (!isStrongPassword(newPassword)) {
            return res.status(400).json({ success: false, message: 'Le nouveau mot de passe doit contenir au moins 8 caractères avec lettres et chiffres.' });
        }

        const resetEntry = await ResetCode.findOne({ email });
        const now = new Date();
        if (!resetEntry || resetEntry.expiresAt <= now) {
            return res.status(400).json({ success: false, message: 'Le code est incorrect ou a expiré !' });
        }
        if (resetEntry.blockedUntil && resetEntry.blockedUntil > now) {
            const retryAfterSeconds = Math.ceil((resetEntry.blockedUntil.getTime() - now.getTime()) / 1000);
            res.set('Retry-After', String(retryAfterSeconds));
            return res.status(429).json({
                success: false,
                message: 'Vous avez fait 3 tentatives incorrectes. Réessayez dans 10 minutes.'
            });
        }
        const submittedHash = Buffer.from(hashResetCode(code), 'hex');
        const expectedHash = Buffer.from(resetEntry.codeHash, 'hex');
        const isCorrectCode = submittedHash.length === expectedHash.length
            && crypto.timingSafeEqual(submittedHash, expectedHash);
        if (!isCorrectCode) {
            const failedAttempt = await ResetCode.findOneAndUpdate(
                {
                    _id: resetEntry._id,
                    codeHash: resetEntry.codeHash,
                    attempts: { $lt: PASSWORD_RESET_MAX_ATTEMPTS },
                    $or: [{ blockedUntil: null }, { blockedUntil: { $lte: now } }]
                },
                { $inc: { attempts: 1 } },
                { new: true }
            ).select('attempts');
            const currentEntry = failedAttempt || await ResetCode.findById(resetEntry._id)
                .select('attempts blockedUntil');
            if (!currentEntry) {
                return res.status(400).json({ success: false, message: 'Le code est incorrect ou a expiré !' });
            }
            if (currentEntry.blockedUntil && currentEntry.blockedUntil > now) {
                const retryAfterSeconds = Math.ceil((currentEntry.blockedUntil.getTime() - now.getTime()) / 1000);
                res.set('Retry-After', String(retryAfterSeconds));
                return res.status(429).json({
                    success: false,
                    message: 'Trop de codes incorrects. Réessayez dans 10 minutes. Si votre demande est valide, un nouveau code a été envoyé par e-mail.',
                    retryAfterSeconds
                });
            }
            if (currentEntry.attempts >= PASSWORD_RESET_MAX_ATTEMPTS) {
                const blockedUntil = new Date(Date.now() + PASSWORD_RESET_LOCKOUT_MS);
                const replacementCode = createResetCode();
                const replacementEntry = await ResetCode.findOneAndUpdate(
                    {
                        _id: resetEntry._id,
                        codeHash: resetEntry.codeHash,
                        attempts: { $gte: PASSWORD_RESET_MAX_ATTEMPTS },
                        $or: [{ blockedUntil: null }, { blockedUntil: { $lte: now } }]
                    },
                    {
                        $set: {
                            codeHash: hashResetCode(replacementCode),
                            attempts: 0,
                            blockedUntil,
                            lastSentAt: new Date(),
                            expiresAt: new Date(Date.now() + PASSWORD_RESET_CODE_TTL_MS)
                        }
                    },
                    { new: true }
                );
                if (!replacementEntry) {
                    const latestEntry = await ResetCode.findById(resetEntry._id).select('blockedUntil');
                    const retryAfterSeconds = latestEntry?.blockedUntil
                        ? Math.max(1, Math.ceil((latestEntry.blockedUntil.getTime() - Date.now()) / 1000))
                        : PASSWORD_RESET_LOCKOUT_MS / 1000;
                    res.set('Retry-After', String(retryAfterSeconds));
                    return res.status(429).json({
                        success: false,
                        message: 'Trop de codes incorrects. Réessayez dans 10 minutes. Si votre demande est valide, un nouveau code a été envoyé par e-mail.',
                        retryAfterSeconds
                    });
                }
                try {
                    await sendPasswordResetCode(email, replacementCode);
                } catch (error) {
                    console.error('Replacement password reset email failed:', error);
                    res.set('Retry-After', String(PASSWORD_RESET_LOCKOUT_MS / 1000));
                    return res.status(503).json({
                        success: false,
                        message: 'Trop de codes incorrects. Réessayez dans 10 minutes. Le nouvel e-mail n’a pas pu être envoyé; veuillez demander un nouveau code après ce délai.'
                    });
                }
                res.set('Retry-After', String(Math.ceil(PASSWORD_RESET_LOCKOUT_MS / 1000)));
                return res.status(429).json({
                    success: false,
                    message: 'Trop de codes incorrects. Réessayez dans 10 minutes. Si votre demande est valide, un nouveau code a été envoyé par e-mail.',
                    retryAfterSeconds: PASSWORD_RESET_LOCKOUT_MS / 1000
                });
            }
            return res.status(400).json({
                success: false,
                message: `Code incorrect. Il vous reste ${PASSWORD_RESET_MAX_ATTEMPTS - currentEntry.attempts} tentative(s).`
            });
        }

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ success: false, message: 'Cet utilisateur n\'existe pas.' });
        }

        user.password = await bcrypt.hash(newPassword, 10);
        user.loginFailedAttempts = 0;
        user.loginBlockedUntil = null;
        await user.save();

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

app.get('/api/course-prices', async (req, res) => {
    try {
        const prices = await CoursePrice.find().select('courseId amount currencyCode').lean();
        res.set('Cache-Control', 'no-store');
        res.json({
            success: true,
            prices: COURSE_ACCESS_CATEGORIES.map((courseId) => {
                const price = prices.find((item) => item.courseId === courseId);
                return {
                    courseId,
                    courseName: COURSE_TITLES[courseId],
                    amount: price?.amount ?? COURSE_PRICE_DEFAULT_AMOUNT,
                    currencyCode: COURSE_PAYMENT_CURRENCY
                };
            })
        });
    } catch (error) {
        console.error('List course prices error:', error);
        res.status(500).json({ success: false, message: 'Impossible de consulter les tarifs des formations.' });
    }
});

app.get('/api/admin/course-prices', requireCourseAdmin, async (req, res) => {
    try {
        const prices = await CoursePrice.find().select('courseId amount currencyCode updatedAt').lean();
        res.json({
            success: true,
            prices: COURSE_ACCESS_CATEGORIES.map((courseId) => {
                const price = prices.find((item) => item.courseId === courseId);
                return {
                    courseId,
                    courseName: COURSE_TITLES[courseId],
                    amount: price?.amount ?? COURSE_PRICE_DEFAULT_AMOUNT,
                    currencyCode: COURSE_PAYMENT_CURRENCY,
                    updatedAt: price?.updatedAt || null
                };
            })
        });
    } catch (error) {
        console.error('Admin list course prices error:', error);
        res.status(500).json({ success: false, message: 'Impossible de consulter les tarifs des formations.' });
    }
});

app.put('/api/admin/course-prices/:courseId', requireCourseAdmin, async (req, res) => {
    try {
        const courseId = String(req.params.courseId || '');
        const amount = Number(req.body?.amount);
        if (!COURSE_ACCESS_CATEGORIES.includes(courseId)
            || !Number.isSafeInteger(amount)
            || amount < 1
            || amount > 100000000) {
            return res.status(400).json({
                success: false,
                message: 'Choisissez une formation valide et un tarif entier en gourdes compris entre 1 et 100 000 000.'
            });
        }

        const price = await CoursePrice.findOneAndUpdate(
            { courseId },
            { $set: { amount, currencyCode: COURSE_PAYMENT_CURRENCY } },
            { new: true, upsert: true, runValidators: true, setDefaultsOnInsert: true }
        ).select('courseId amount currencyCode updatedAt');
        res.json({ success: true, price });
    } catch (error) {
        console.error('Update course price error:', error);
        res.status(500).json({ success: false, message: 'Impossible d’enregistrer le tarif de cette formation.' });
    }
});

app.post('/api/pay-tranzak', authenticate, async (req, res) => {
    let payment;
    try {
        const apiKey = String(process.env.TRANZAK_API_KEY || '').trim();
        if (!apiKey || !process.env.TRANZAK_WEBHOOK_SECRET) {
            return res.status(503).json({ success: false, message: 'Le paiement Tranzak n’est pas encore configuré.' });
        }

        const courseId = String(req.body?.courseId || '');
        if (!COURSE_ACCESS_CATEGORIES.includes(courseId)) {
            return res.status(400).json({ success: false, message: 'Choisissez une formation valide.' });
        }
        const paymentMethod = String(req.body?.paymentMethod || 'moncash').trim().toLowerCase();
        if (!['moncash', 'natcash', 'card'].includes(paymentMethod)) {
            return res.status(400).json({ success: false, message: 'Choisissez un moyen de paiement Tranzak valide.' });
        }
        const user = await User.findById(req.user.id).select('_id name email');
        if (!user) {
            return res.status(404).json({ success: false, message: 'Votre compte étudiant est introuvable.' });
        }
        if (await CourseEnrollmentAccess.exists({ userId: user._id, courseId })) {
            return res.status(409).json({ success: false, message: 'Vous avez déjà accès à cette formation.' });
        }
        const price = await CoursePrice.findOne({ courseId }).select('amount currencyCode');
        if (!price) {
            return res.status(503).json({ success: false, message: 'Le tarif de cette formation n’est pas disponible.' });
        }

        const mchTransactionRef = `CA${crypto.randomBytes(15).toString('hex')}`;
        payment = await CoursePayment.create({
            userId: user._id,
            courseId,
            provider: 'tranzak',
            paymentMethod,
            amount: price.amount,
            currencyCode: COURSE_PAYMENT_CURRENCY,
            mchTransactionRef
        });

        let tranzakResponse;
        try {
            tranzakResponse = await fetch(getTranzakPaymentsUrl(), {
                method: 'POST',
                headers: getTranzakHeaders(apiKey),
                body: JSON.stringify({
                    amount: price.amount,
                    currency: COURSE_PAYMENT_CURRENCY,
                    payment_method: paymentMethod,
                    customer_name: user.name,
                    customer_email: user.email,
                    reference: mchTransactionRef,
                    description: `Paiement du cours ${COURSE_TITLES[courseId]}`,
                    metadata: {
                        user_id: String(user._id),
                        course_id: courseId
                    }
                }),
                signal: AbortSignal.timeout(20000)
            });
        } catch (cause) {
            const error = new Error('Tranzak checkout could not be reached.');
            error.cause = cause;
            error.code = 'TRANZAK_UNAVAILABLE';
            throw error;
        }

        const responseBody = await tranzakResponse.text();
        let checkout;
        try {
            checkout = JSON.parse(responseBody);
        } catch (cause) {
            const error = new Error(`Tranzak returned an invalid payment response (${tranzakResponse.status}).`);
            error.tranzakResponse = {
                endpoint: getTranzakPaymentsUrl(),
                status: tranzakResponse.status,
                statusText: tranzakResponse.statusText,
                body: responseBody
            };
            throw error;
        }
        const transactionId = String(checkout.transaction_id || '').trim();
        const paymentUrl = String(checkout.payment_url || '').trim();
        const hasCardWidget = Boolean(
            checkout.client_secret
            && checkout.publishable_key
            && checkout.payment_intent_id
        );
        if (!tranzakResponse.ok || !transactionId
            || (paymentMethod === 'card' ? !hasCardWidget : !paymentUrl)) {
            const error = new Error('Tranzak did not return a valid payment session.');
            error.tranzakResponse = {
                endpoint: getTranzakPaymentsUrl(),
                status: tranzakResponse.status,
                statusText: tranzakResponse.statusText,
                body: responseBody
            };
            throw error;
        }

        let securePaymentUrl;
        if (paymentMethod !== 'card') {
            try {
                securePaymentUrl = new URL(paymentUrl);
            } catch (cause) {
                throw new Error('Tranzak returned an invalid payment URL.');
            }
            if (securePaymentUrl.protocol !== 'https:') {
                throw new Error('Tranzak returned a non-secure payment URL.');
            }
        }

        const storedCheckout = await CoursePayment.updateOne({ _id: payment._id }, {
            $set: {
                requestId: transactionId,
                ...(checkout.status === 'completed' ? { status: 'SUCCESSFUL', paidAt: new Date() } : {})
            }
        });
        if (!storedCheckout.matchedCount) {
            throw new Error('The Tranzak checkout reference could not be saved.');
        }
        const response = {
            success: true,
            reference: mchTransactionRef,
            transactionId,
            paymentMethod,
            amount: price.amount,
            currencyCode: COURSE_PAYMENT_CURRENCY
        };
        if (paymentMethod === 'card') {
            response.clientSecret = checkout.client_secret;
            response.publishableKey = checkout.publishable_key;
            response.paymentIntentId = checkout.payment_intent_id;
        } else {
            response.paymentUrl = securePaymentUrl.href;
        }
        res.json(response);
    } catch (error) {
        if (error.tranzakResponse) {
            console.log('Tranzak API complete error response:', error.tranzakResponse);
        }
        console.error('Create Tranzak course payment error:', {
            message: error.message,
            code: error.code,
            cause: error.cause?.message,
            tranzakResponse: error.tranzakResponse
        });
        if (payment) {
            try {
                await CoursePayment.updateOne(
                    { _id: payment._id, status: 'PENDING' },
                    { $set: { status: 'REJECTED' } }
                );
            } catch (updateError) {
                console.error('Could not mark failed Tranzak checkout:', updateError);
            }
        }
        if (error.code === 'TRANZAK_UNAVAILABLE') {
            return res.status(502).json({ success: false, message: 'Tranzak est temporairement indisponible. Réessayez dans quelques instants.' });
        }
        res.status(502).json({ success: false, message: 'Impossible d’ouvrir le paiement Tranzak. Réessayez dans quelques instants.' });
    }
});

app.get('/api/payments/status', authenticate, async (req, res) => {
    try {
        const reference = String(req.query?.reference || '');
        if (!reference || reference.length > 128 || /[\u0000-\u001f\u007f]/.test(reference)) {
            return res.status(400).json({ success: false, message: 'Référence de paiement invalide.' });
        }
        const payment = await CoursePayment.findOne({
            userId: req.user.id,
            $or: [
                { mchTransactionRef: reference },
                { requestId: reference }
            ]
        }).select('courseId amount currencyCode status accessGrantedAt paidAt provider paymentMethod mchTransactionRef requestId userId');
        if (!payment) {
            return res.status(404).json({ success: false, message: 'Aucun paiement ne correspond à cette référence.' });
        }
        res.set('Cache-Control', 'no-store');
        const response = {
            success: true,
            status: payment.status,
            courseId: payment.courseId,
            courseName: COURSE_TITLES[payment.courseId],
            amount: payment.amount,
            currencyCode: payment.currencyCode,
            paidAt: payment.paidAt
        };
        if (payment.accessGrantedAt) {
            const access = await CourseEnrollmentAccess.findOne({
                userId: req.user.id,
                courseId: payment.courseId
            }).select('+encryptedCode');
            if (access?.encryptedCode) response.accessCode = decryptCourseAccessCode(access.encryptedCode);
        }
        if (payment.status === 'SUCCESSFUL' && payment.accessGrantedAt) {
            const student = await User.findById(payment.userId).select('name');
            response.studentName = student?.name || '';
            response.providerName = payment.provider === 'tranzak'
                ? payment.paymentMethod === 'natcash' ? 'NatCash'
                    : payment.paymentMethod === 'card' ? 'Carte bancaire' : 'MonCash'
                : payment.provider === 'stripe' ? 'Carte bancaire (Visa / Mastercard)'
                    : payment.provider === 'moncash' ? 'MonCash' : 'Natcash';
            response.transactionReference = payment.requestId || payment.mchTransactionRef;
        }
        res.json(response);
    } catch (error) {
        console.error('Read payment status error:', error);
        res.status(500).json({ success: false, message: 'Impossible de consulter le statut de votre paiement.' });
    }
});

app.post('/api/payments/cancel', authenticate, async (req, res) => {
    try {
        const reference = String(req.body?.reference || '');
        if (!reference || reference.length > 128 || /[\u0000-\u001f\u007f]/.test(reference)) {
            return res.status(400).json({ success: false, message: 'Référence de paiement invalide.' });
        }
        const payment = await CoursePayment.findOneAndUpdate({
            userId: req.user.id,
            mchTransactionRef: reference,
            status: 'PENDING'
        }, {
            $set: { status: 'CANCELLED' }
        }, { new: true }).select('_id');
        return res.json({ success: true, cancelled: Boolean(payment) });
    } catch (error) {
        console.error('Cancel course payment error:', error);
        return res.status(500).json({ success: false, message: 'Impossible de mettre à jour le statut du paiement.' });
    }
});

app.post('/api/course-progress/unlock-paid', authenticate, async (req, res) => {
    try {
        const courseId = String(req.body?.courseId || '');
        const accessCode = String(req.body?.accessCode || '').trim();
        const videoIds = Array.isArray(req.body?.videoIds)
            ? [...new Set(req.body.videoIds.map((videoId) => String(videoId || '').trim()))]
            : [];
        if (!COURSE_ACCESS_CATEGORIES.includes(courseId)
            || !accessCode
            || accessCode.length > 128
            || videoIds.length < 1
            || videoIds.length > 100
            || videoIds.some((videoId) => videoId.length > 128 || getCourseForVideo(videoId) !== courseId)) {
            return res.status(400).json({ success: false, message: 'Formation, code ou leçons invalides.' });
        }
        if (!await isValidCourseAccessCode(req.user.id, courseId, accessCode)) {
            return res.status(400).json({ success: false, message: 'Code d’accès incorrect ou expiré.' });
        }

        const progress = await getOrCreateCourseProgress(req.user.id);
        progress.unlockedVideoIds.addToSet(...videoIds);
        await progress.save();
        return res.json({ success: true, progress: serializeCourseProgress(progress) });
    } catch (error) {
        console.error('Unlock paid course videos error:', error);
        return res.status(500).json({ success: false, message: 'Impossible de débloquer les leçons de cette formation.' });
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
        ).select('_id name email avatarUrl nameOnCertificate phone location registeredCourse');
        if (!user) {
            return res.status(404).json({ success: false, message: 'Utilisateur introuvable.' });
        }
        res.json({
            success: true,
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                avatarUrl: user.avatarUrl,
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
                avatarUrl: user.avatarUrl,
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

app.post('/api/auth/heartbeat', authenticate, (req, res) => {
    res.json({ success: true, message: 'Session active.' });
});

app.post('/api/logout', async (req, res) => {
    const token = req.cookies?.ca_token || req.headers.authorization?.replace(/^Bearer\s+/i, '');
    if (token) {
        try {
            const decoded = jwt.verify(token, JWT_SECRET, { ignoreExpiration: true });
            if (decoded.id && decoded.sessionId) {
                const releasedUser = await User.findOneAndUpdate({
                    _id: decoded.id,
                    tokenVersion: decoded.tokenVersion,
                    activeSessionId: decoded.sessionId
                }, {
                    $inc: { tokenVersion: 1 },
                    $set: {
                        isLoggedIn: false,
                        activeSessionId: null,
                        activeSessionExpiresAt: null,
                        activeSessionTokenExpiresAt: null
                    }
                }).select('_id');
                if (releasedUser) io.in(String(releasedUser._id)).disconnectSockets(true);
            }
        } catch (error) {
            console.error('Logout session release failed:', error);
            clearAuthCookie(res);
            return res.status(500).json({
                success: false,
                message: 'Impossible de fermer complètement la session. Réessayez.'
            });
        }
    }
    clearAuthCookie(res);
    res.json({ success: true, message: 'Déconnexion réussie' });
});

app.post('/api/auth/logout', authenticate, async (req, res) => {
    try {
        const releasedUser = await User.findOneAndUpdate({
            _id: req.user.id,
            tokenVersion: req.user.tokenVersion,
            activeSessionId: req.user.sessionId
        }, {
            $inc: { tokenVersion: 1 },
            $set: {
                isLoggedIn: false,
                activeSessionId: null,
                activeSessionExpiresAt: null,
                activeSessionTokenExpiresAt: null
            }
        }).select('_id');

        clearAuthCookie(res);
        if (!releasedUser) {
            return res.status(401).json({ success: false, message: 'Session expirée ou invalide.' });
        }

        io.in(String(releasedUser._id)).disconnectSockets(true);
        return res.json({ success: true, message: 'Déconnexion réussie' });
    } catch (error) {
        console.error('Authenticated logout failed:', error);
        clearAuthCookie(res);
        return res.status(500).json({ success: false, message: 'Impossible de fermer complètement la session.' });
    }
});

// Count authenticated students, not browser tabs or devices.
const onlineUsers = new Map();

io.on('connection', (socket) => {
    const userId = socket.data.userId;
    let sessionExpiryTimer;
    const scheduleSessionExpiry = () => {
        clearTimeout(sessionExpiryTimer);
        sessionExpiryTimer = setTimeout(
            () => socket.disconnect(true),
            Math.max(0, socket.data.sessionExpiresAt - Date.now())
        );
    };
    scheduleSessionExpiry();
    const userSockets = onlineUsers.get(userId) || new Set();
    userSockets.add(socket.id);
    onlineUsers.set(userId, userSockets);
    io.emit('onlineCount', onlineUsers.size);

    socket.on('sessionHeartbeat', async () => {
        try {
            const now = new Date();
            const refreshedUser = await User.findOneAndUpdate({
                _id: userId,
                tokenVersion: socket.data.tokenVersion,
                activeSessionId: socket.data.sessionId,
                activeSessionExpiresAt: { $gt: now },
                activeSessionTokenExpiresAt: { $gt: now }
            }, {
                $set: {
                    activeSessionExpiresAt: new Date(Math.min(
                        now.getTime() + SESSION_IDLE_TIMEOUT_MS,
                        socket.data.sessionTokenExpiresAt
                    ))
                }
            }, { new: true }).select('activeSessionExpiresAt');
            if (!refreshedUser) {
                socket.disconnect(true);
                return;
            }
            socket.data.sessionExpiresAt = refreshedUser.activeSessionExpiresAt.getTime();
            scheduleSessionExpiry();
        } catch (error) {
            console.error('Socket session heartbeat failed:', error);
            socket.disconnect(true);
        }
    });

    socket.on('disconnect', () => {
        clearTimeout(sessionExpiryTimer);
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
        ADMIN_JWT_SECRET,
        ALLOWED_ADMIN_EMAILS: getAllowedAdminEmails().join(','),
        MONGODB_URI,
        GOOGLE_CLIENT_ID,
        FRONTEND_URLS: FRONTEND_URLS.join(',')
    };
    const missingEnvironment = Object.keys(requiredEnvironment).filter((key) => !requiredEnvironment[key]);
    const configuredAdminEmails = getAllowedAdminEmails();
    if (configuredAdminEmails.length !== 3
        || new Set(configuredAdminEmails).size !== 3
        || configuredAdminEmails.some((email) => !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))) {
        throw new Error('ALLOWED_ADMIN_EMAILS must contain exactly three distinct valid comma-separated email addresses.');
    }
    if (Buffer.byteLength(ADMIN_JWT_SECRET || '', 'utf8') < 32) {
        throw new Error('ADMIN_JWT_SECRET must contain at least 32 bytes of random data and be shared with Quiz Backend.');
    }
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
    if (!process.env.TRANZAK_API_KEY || !process.env.TRANZAK_WEBHOOK_SECRET) {
        console.warn('Tranzak payments require TRANZAK_API_KEY and TRANZAK_WEBHOOK_SECRET.');
    } else {
        console.log(`Tranzak API configured (${getTranzakApiBaseUrl()}).`);
    }

    await mongoose.connect(MONGODB_URI, {
        serverSelectionTimeoutMS: 10000
    });
    console.log('MongoDB connected');
    await CoursePrice.bulkWrite(COURSE_ACCESS_CATEGORIES.map((courseId) => ({
        updateOne: {
            filter: { courseId },
            update: {
                $setOnInsert: {
                    courseId,
                    amount: COURSE_PRICE_DEFAULT_AMOUNT,
                    currencyCode: COURSE_PAYMENT_CURRENCY
                }
            },
            upsert: true
        }
    })));
    console.log('Course prices initialized');

    server.listen(PORT, () => {
        console.log(`Server Competence Academy Run ${PORT}`);
        const keepAliveUrl = new URL('/api/ping', process.env.RENDER_EXTERNAL_URL || `http://127.0.0.1:${PORT}`);
        const keepAliveTimer = setInterval(async () => {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 10000);
            try {
                const response = await fetch(keepAliveUrl, { signal: controller.signal });
                if (!response.ok) {
                    console.warn(`Keep-alive ping returned HTTP ${response.status}.`);
                }
            } catch (error) {
                console.warn('Keep-alive ping failed:', error.message);
            } finally {
                clearTimeout(timeoutId);
            }
        }, 600000);
        keepAliveTimer.unref();
    });
};

startServer().catch((error) => {
    console.error('Server startup failed:', error.message);
    process.exit(1);
});
