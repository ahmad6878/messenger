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

const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'uploads/'),
    filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({ storage: storage });

db.exec(`
  CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT);
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT, sender_id INTEGER, receiver_id INTEGER,
    text TEXT, type TEXT DEFAULT 'text', file_url TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

const insertUser = db.prepare('INSERT INTO users (username, password) VALUES (?, ?)');
const getUserByUsername = db.prepare('SELECT * FROM users WHERE username = ?');
const getUserById = db.prepare('SELECT id, username FROM users WHERE id = ?');
const searchUsersQuery = db.prepare('SELECT id, username FROM users WHERE username LIKE ? AND id != ? LIMIT 20');
const insertMessage = db.prepare('INSERT INTO messages (sender_id, receiver_id, text, type, file_url) VALUES (?, ?, ?, ?, ?)');
const getChatHistory = db.prepare(`
  SELECT m.*, u.username as sender_username
  FROM messages m JOIN users u ON m.sender_id = u.id
  WHERE (m.sender_id = ? AND m.receiver_id = ?) OR (m.sender_id = ? AND m.receiver_id = ?)
  ORDER BY m.timestamp ASC
`);
const getRecentChats = db.prepare(`
  SELECT contact_id, MAX(timestamp) as last_time FROM (
    SELECT receiver_id as contact_id, timestamp FROM messages WHERE sender_id = ?
    UNION ALL
    SELECT sender_id as contact_id, timestamp FROM messages WHERE receiver_id = ?
  ) GROUP BY contact_id ORDER BY last_time DESC
`);

const server = http.createServer((req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Content-Type', 'application/json');

    const authenticate = (req) => {
        try { return jwt.verify(req.headers['authorization'].split(' ')[1], SECRET_KEY); }
        catch { return null; }
    };

    if (req.url === '/api/upload' && req.method === 'POST') {
        const auth = authenticate(req);
        if (!auth) { res.writeHead(401); res.end(JSON.stringify({error:'Unauthorized'})); return; }
        upload.single('file')(req, res, (err) => {
            if (err || !req.file) { res.end(JSON.stringify({error:'Upload failed'})); return; }
            res.end(JSON.stringify({ file_url: `/uploads/${req.file.filename}` }));
        });
        return;
    }

    if (req.url === '/api/register' && req.method === 'POST') {
        let b = ''; req.on('data', c => b += c);
        req.on('end', () => {
            try {
                const {username, password} = JSON.parse(b);
                if (!username || !password) { res.end(JSON.stringify({success:false, error:'Заполните все поля'})); return; }
                insertUser.run(username, bcrypt.hashSync(password, 10));
                res.end(JSON.stringify({success:true}));
            } catch(e) {
                res.end(JSON.stringify({success:false, error:'Пользователь уже существует'}));
            }
        });
        return;
    }

    if (req.url === '/api/login' && req.method === 'POST') {
        let b = ''; req.on('data', c => b += c);
        req.on('end', () => {
            try {
                const {username, password} = JSON.parse(b);
                const u = getUserByUsername.get(username);
                if (u && bcrypt.compareSync(password, u.password)) {
                    res.end(JSON.stringify({
                        success: true,
                        token: jwt.sign({userId: u.id, username: u.username}, SECRET_KEY),
                        user: {id: u.id, username: u.username}
                    }));
                } else {
                    res.end(JSON.stringify({success:false, error:'Неверный логин или пароль'}));
                }
            } catch(e) {
                res.end(JSON.stringify({success:false, error:'Ошибка сервера'}));
            }
        });
        return;
    }

    if (req.url.startsWith('/api/search')) {
        const a = authenticate(req);
        if (!a) { res.writeHead(401); res.end('[]'); return; }
        const q = new URL(req.url, `http://${req.headers.host}`).searchParams.get('q') || '';
        res.end(JSON.stringify(searchUsersQuery.all(`%${q}%`, a.userId)));
        return;
    }

    if (req.url === '/api/chats') {
        const a = authenticate(req);
        if (!a) { res.writeHead(401); res.end('[]'); return; }
        const chats = getRecentChats.all(a.userId, a.userId).map(r => getUserById.get(r.contact_id)).filter(Boolean);
        res.end(JSON.stringify(chats));
        return;
    }

    if (req.url.startsWith('/api/messages/')) {
        const a = authenticate(req);
        if (!a) { res.writeHead(401); res.end('[]'); return; }
        const otherId = req.url.split('/').pop();
        res.end(JSON.stringify(getChatHistory.all(a.userId, otherId, otherId, a.userId)));
        return;
    }

    if (req.url.startsWith('/api/user/')) {
        const a = authenticate(req);
        if (!a) { res.writeHead(401); res.end('{}'); return; }
        const userId = req.url.split('/').pop();
        const user = getUserById.get(parseInt(userId));
        res.end(JSON.stringify(user || {}));
        return;
    }

    if (req.url.startsWith('/uploads/')) {
        const p = path.join(__dirname, req.url);
        if (fs.existsSync(p)) {
            res.setHeader('Content-Type', '');
            fs.createReadStream(p).pipe(res);
        } else {
            res.writeHead(404); res.end('Not found');
        }
        return;
    }

    res.setHeader('Content-Type', 'text/html');
    const f = req.url === '/' ? '/index.html' : req.url;
    fs.readFile(path.join(__dirname, f), (err, data) => {
        if (err) { res.writeHead(404); res.end('Not found'); return; }
        res.end(data);
    });
});

const wss = new WebSocket.Server({ server });
const clients = new Map();

wss.on('connection', (ws) => {
    let uid = null;
    ws.on('message', (msg) => {
        try {
            const d = JSON.parse(msg);

            if (d.type === 'auth') {
                try {
                    uid = jwt.verify(d.token, SECRET_KEY).userId;
                    clients.set(uid, ws);
                } catch(e) { ws.close(); }
                return;
            }

            if (!uid) return;

            if (d.type === 'private_message') {
                const r = insertMessage.run(uid, d.receiverId, d.text || '', d.msgType || 'text', d.fileUrl || null);
                const sender = getUserById.get(uid);
                const obj = {
                    type: 'private_message',
                    id: r.lastInsertRowid,
                    sender_id: uid,
                    receiver_id: Number(d.receiverId),
                    text: d.text || '',
                    msgType: d.msgType || 'text',
                    file_url: d.fileUrl || null,
                    sender_username: sender ? sender.username : '',
                    timestamp: new Date().toISOString()
                };
                const target = clients.get(Number(d.receiverId));
                if (target && target.readyState === WebSocket.OPEN) target.send(JSON.stringify(obj));
                ws.send(JSON.stringify(obj));
                return;
            }

            if (d.receiverId) {
                const target = clients.get(Number(d.receiverId));
                if (target && target.readyState === WebSocket.OPEN) {
                    target.send(JSON.stringify({ ...d, sender_id: uid }));
                }
            }
        } catch(e) { console.error('Ошибка:', e); }
    });
    ws.on('close', () => { if (uid) clients.delete(uid); });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`✅ Сервер запущен на http://localhost:${PORT}`));