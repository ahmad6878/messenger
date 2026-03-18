const http = require('http');
const WebSocket = require('ws');
const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');

const SECRET_KEY = 'my_super_secret_messenger_key';
const db = new Database('messenger.db');

// Папка для загрузок
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

// Настройка Multer для сохранения файлов
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'uploads/'),
    filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({ storage: storage });

db.exec(`
  CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT);
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT, 
    sender_id INTEGER, 
    receiver_id INTEGER, 
    text TEXT, 
    type TEXT DEFAULT 'text', 
    file_url TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

const insertUser = db.prepare('INSERT INTO users (username, password) VALUES (?, ?)');
const getUserByUsername = db.prepare('SELECT * FROM users WHERE username = ?');
const getUserById = db.prepare('SELECT id, username FROM users WHERE id = ?');
const searchUsersQuery = db.prepare('SELECT id, username FROM users WHERE username LIKE ? AND id != ? LIMIT 20');
const insertMessage = db.prepare('INSERT INTO messages (sender_id, receiver_id, text, type, file_url) VALUES (?, ?, ?, ?, ?)');
const getChatHistory = db.prepare(`
  SELECT m.*, u.username as sender_username FROM messages m
  JOIN users u ON m.sender_id = u.id
  WHERE (m.sender_id = ? AND m.receiver_id = ?) OR (m.sender_id = ? AND m.receiver_id = ?)
  ORDER BY m.timestamp ASC
`);
const getRecentChats = db.prepare(`
  SELECT contact_id, MAX(timestamp) as last_time FROM (
    SELECT receiver_id as contact_id, timestamp FROM messages WHERE sender_id = ?
    UNION ALL SELECT sender_id as contact_id, timestamp FROM messages WHERE receiver_id = ?
  ) GROUP BY contact_id ORDER BY last_time DESC
`);

const server = http.createServer((req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    const authenticate = (req) => {
        try { return jwt.verify(req.headers['authorization'].split(' ')[1], SECRET_KEY); } catch { return null; }
    };

    // API для загрузки медиа/голосовых
    if (req.url === '/api/upload' && req.method === 'POST') {
        const authUser = authenticate(req);
        if (!authUser) { res.writeHead(401); res.end(); return; }

        upload.single('file')(req, res, (err) => {
            if (err) { res.writeHead(500); res.end(); return; }
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ file_url: `/uploads/${req.file.filename}` }));
        });
        return;
    }

    if (req.url === '/api/register' && req.method === 'POST') {
        let body = ''; req.on('data', c => body += c);
        req.on('end', () => {
            try {
                const {username, password} = JSON.parse(body);
                insertUser.run(username, bcrypt.hashSync(password, 10));
                res.end(JSON.stringify({success:true}));
            } catch(e) { res.end(JSON.stringify({success:false, message: 'Ошибка'})); }
        }); return;
    }

    if (req.url === '/api/login' && req.method === 'POST') {
        let body = ''; req.on('data', c => body += c);
        req.on('end', () => {
            const {username, password} = JSON.parse(body);
            const user = getUserByUsername.get(username);
            if (user && bcrypt.compareSync(password, user.password)) {
                const token = jwt.sign({userId: user.id, username: user.username}, SECRET_KEY);
                res.end(JSON.stringify({success:true, token, user: {id:user.id, username:user.username}}));
            } else res.end(JSON.stringify({success:false}));
        }); return;
    }

    if (req.url.startsWith('/api/search')) {
        const auth = authenticate(req);
        const query = new URL(req.url, `http://${req.headers.host}`).searchParams.get('q');
        res.end(JSON.stringify(searchUsersQuery.all(`%${query}%`, auth.userId))); return;
    }

    if (req.url === '/api/chats') {
        const auth = authenticate(req);
        const ids = getRecentChats.all(auth.userId, auth.userId);
        res.end(JSON.stringify(ids.map(r => getUserById.get(r.contact_id)))); return;
    }

    if (req.url.startsWith('/api/messages/')) {
        const auth = authenticate(req);
        const otherId = req.url.split('/').pop();
        res.end(JSON.stringify(getChatHistory.all(auth.userId, otherId, otherId, auth.userId))); return;
    }

    // Раздача файлов из папки uploads
    if (req.url.startsWith('/uploads/')) {
        const filePath = path.join(__dirname, req.url);
        if (fs.existsSync(filePath)) { fs.createReadStream(filePath).pipe(res); }
        else { res.writeHead(404); res.end(); }
        return;
    }

    const file = req.url === '/' ? '/index.html' : req.url;
    fs.readFile(path.join(__dirname, file), (err, data) => {
        if (err) { res.writeHead(404); res.end(); }
        else { res.end(data); }
    });
});

const wss = new WebSocket.Server({ server });
const clients = new Map();

wss.on('connection', (ws) => {
    let uid = null;
    ws.on('message', (msg) => {
        const data = JSON.parse(msg);
        if (data.type === 'auth') {
            try { uid = jwt.verify(data.token, SECRET_KEY).userId; clients.set(uid, ws); } catch(e) { ws.close(); }
        }
        if (data.type === 'private_message' && uid) {
            const {receiverId, text, msgType, fileUrl} = data;
            const res = insertMessage.run(uid, receiverId, text || '', msgType || 'text', fileUrl || null);
            const obj = { type: 'private_message', id: res.lastInsertRowid, sender_id: uid, receiver_id: receiverId, text, msgType: msgType || 'text', file_url: fileUrl, timestamp: new Date() };
            if (clients.has(receiverId)) clients.get(receiverId).send(JSON.stringify(obj));
            ws.send(JSON.stringify(obj));
        }
    });
    ws.on('close', () => clients.delete(uid));
});

server.listen(process.env.PORT || 3000);
