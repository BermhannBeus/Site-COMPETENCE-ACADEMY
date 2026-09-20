const express = require('express');
const http = require('http');
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
        origin: "*",
        methods: ["GET", "POST"]
    }
});

const PORT = process.env.PORT || 5000;
const JWT_SECRET = 'competence_academy_secret_key_2026';

// Client ID Google
const GOOGLE_CLIENT_ID = '745679796774-7jodshecnt3upfn3g307q24sn8fm91it.apps.googleusercontent.com';
const client = new OAuth2Client(GOOGLE_CLIENT_ID);

// Configuration Nodemailer
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'competenceacademy34@gmail.com',
        pass: 'evrqohwdlrrllcum' // Mot de passe d'application Google
    }
});

// Middleware
app.use(express.json());
app.use(cors());

// Stockage en mémoire
const users = [];
const resetCodes = {}; // Stockage temporaire des codes à 6 chiffres

// 1. ROUTE POU SIGNUP (Enskripsyon)
app.post('/api/signup', async (req, res) => {
    try {
        const { name, email, password } = req.body;

        const existingUser = users.find(u => u.email === email);
        if (existingUser) {
            return res.status(400).json({ success: false, message: 'Imèl sa a deja anrejistre deja!' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = { id: Date.now().toString(), name, email, password: hashedPassword };
        users.push(newUser);

        const token = jwt.sign({ id: newUser.id, email: newUser.email }, JWT_SECRET, { expiresIn: '1h' });

        res.status(201).json({
            success: true,
            message: 'Kont ou an kreye avèk siksè!',
            token,
            user: { id: newUser.id, name: newUser.name, email: newUser.email }
        });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Gen yon erè sou sèvè a.' });
    }
});

// 2. ROUTE POU LOGIN (Koneksyon)
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = users.find(u => u.email === email);
        if (!user) {
            return res.status(400).json({ success: false, message: 'Imèl sa a oswa modpas la pa kòrèk.' });
        }

        // Tcheke si kont lan te kreye ak Google san modpas
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

        const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '1h' });

        res.json({
            success: true,
            message: 'Ou konekte avèk siksè!',
            token,
            user: { id: user.id, name: user.name, email: user.email }
        });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Gen yon erè sou sèvè a.' });
    }
});

// 3. ROUTE POU GOOGLE LOGIN / SIGNUP OTOMATIK
app.post('/api/google-login', async (req, res) => {
    try {
        const { token } = req.body;

        const ticket = await client.verifyIdToken({
            idToken: token,
            audience: GOOGLE_CLIENT_ID
        });

        const payload = ticket.getPayload();
        const { email, name, sub: googleId } = payload;

        let user = users.find(u => u.email === email);

        if (!user) {
            user = {
                id: googleId,
                name: name,
                email: email,
                password: ''
            };
            users.push(user);
        }

        const appToken = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '1h' });

        res.json({
            success: true,
            message: 'Koneksyon Google reyekti avèk siksè!',
            token: appToken,
            user: { id: user.id, name: user.name, email: user.email }
        });

    } catch (error) {
        console.error(error);
        res.status(400).json({ success: false, message: 'Token Google la pa valab.' });
    }
});

// 4. ROUTE POU MANDE KÒD REKIPERASYON (ENVOI DU CODE À 6 CHIFFRES)
app.post('/api/forgot-password', async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ success: false, message: 'Veuillez fournir un email valide.' });
    }

    try {
        const resetCode = Math.floor(100000 + Math.random() * 900000).toString();
        resetCodes[email] = resetCode;

        const mailOptions = {
            from: '"Competence Academy" <competenceacademy34@gmail.com>',
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
app.post('/api/reset-password-code', async (req, res) => {
    try {
        const { email, code, newPassword } = req.body;

        if (!email || !code || !newPassword) {
            return res.status(400).json({ success: false, message: 'Veuillez remplir tous les champs.' });
        }

        if (resetCodes[email] !== code) {
            return res.status(400).json({ success: false, message: 'Le code est incorrect ou a expiré !' });
        }

        const user = users.find(u => u.email === email);
        if (!user) {
            return res.status(404).json({ success: false, message: 'Cet utilisateur n\'existe pas.' });
        }

        user.password = await bcrypt.hash(newPassword, 10);
        delete resetCodes[email];

        res.json({ success: true, message: 'Votre mot de passe a été modifié avec succès !' });

    } catch (error) {
        res.status(500).json({ success: false, message: 'Erreur sur le serveur.' });
    }
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

// Démarrage du serveur
server.listen(PORT, () => {
    console.log(`Server Competence Academy Run ${PORT}`);
});