const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');

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

// Mete vrè ID client Google ou an isit la
const GOOGLE_CLIENT_ID = '745679796774-7jodshecnt3upfn3g307q24sn8fm91it.apps.googleusercontent.com';
const client = new OAuth2Client(GOOGLE_CLIENT_ID);

// Middleware
app.use(express.json());
app.use(cors());

// Yon ti baz done an memwa (pou tès la)
const users = [];

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

        // Verifye si token Google la otantik
        const ticket = await client.verifyIdToken({
            idToken: token,
            audience: GOOGLE_CLIENT_ID
        });

        const payload = ticket.getPayload();
        const { email, name, sub: googleId } = payload;

        // Tcheke si itilizatè a deja egziste nan baz done an memwa
        let user = users.find(u => u.email === email);

        if (!user) {
            // Si l pa egziste, nou kreye l otomatikman sou plas!
            user = {
                id: googleId,
                name: name,
                email: email,
                password: '' // Pa gen modpas nesesè pou Google Sign-In
            };
            users.push(user);
        }

        // Kreye yon JWT token pou sesyon aplikasyon an
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

// Gestion du nombre d'utilisateurs en ligne
let onlineUsers = 0;

io.on('connection', (socket) => {
    onlineUsers++;
    io.emit('updateOnlineCount', onlineUsers);

    socket.on('disconnect', () => {
        onlineUsers--;
        io.emit('updateOnlineCount', onlineUsers);
    });
});

// Lè w ap lanse sèvè a, nou itilize server.listen olye de app.listen pou Socket.io ka mache
server.listen(PORT, () => {
    console.log(`Server Competence Academy Run ${PORT}`);
});

