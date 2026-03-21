const http = require('http');
const WebSocket = require('ws');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { Pool } = require('pg');

const SECRET_KEY = 'my_super_secret_messenger_key';

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'uploads/'),
    filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({ storage: storage });

async function initDB() {
    await pool.query(`
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS messages (
            id SERIAL PRIMARY KEY,
            sender_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            receiver_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            text TEXT DEFAULT '',
            type TEXT DEFAULT 'text',
            file_url TEXT,
            timestamp TIMESTAMPTZ DEFAULT NOW()
        );
    `);
    console.log('✅ База данных готова');
}

const server = http.createServer(async (req, res) => {
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
        req.on('end', async () => {
            try {
                const {username, password} = JSON.parse(b);
                if (!username || !password) { res.end(JSON.stringify({success:false, error:'Заполните все поля'})); return; }
                await pool.query('INSERT INTO users (username, password) VALUES ($1, $2)', [username, bcrypt.hashSync(password, 10)]);
                res.end(JSON.stringify({success:true}));
            } catch(e) {
                res.end(JSON.stringify({success:false, error:'Пользователь уже существует'}));
            }
        });
        return;
    }

    if (req.url === '/api/login' && req.method === 'POST') {
        let b = ''; req.on('data', c => b += c);
        req.on('end', async () => {
            try {
                const {username, password} = JSON.parse(b);
                const r = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
                const u = r.rows[0];
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

    if (req.url === '/api/delete-account' && req.method === 'DELETE') {
        const a = authenticate(req);
        if (!a) { res.writeHead(401); res.end(JSON.stringify({error:'Unauthorized'})); return; }
        try {
            await pool.query('DELETE FROM users WHERE id = $1', [a.userId]);
            res.end(JSON.stringify({success:true}));
        } catch(e) {
            res.end(JSON.stringify({success:false, error:'Ошибка удаления'}));
        }
        return;
    }

    if (req.url.startsWith('/api/search')) {
        const a = authenticate(req);
        if (!a) { res.writeHead(401); res.end('[]'); return; }
        const q = new URL(req.url, `http://${req.headers.host}`).searchParams.get('q') || '';
        const r = await pool.query('SELECT id, username FROM users WHERE username ILIKE $1 AND id != $2 LIMIT 20', [`%${q}%`, a.userId]);
        res.end(JSON.stringify(r.rows));
        return;
    }

    if (req.url === '/api/chats') {
        const a = authenticate(req);
        if (!a) { res.writeHead(401); res.end('[]'); return; }
        const r = await pool.query(`
            SELECT contact_id, MAX(last_time) as last_time FROM (
                SELECT receiver_id as contact_id, MAX(timestamp) as last_time FROM messages WHERE sender_id = $1 GROUP BY receiver_id
                UNION ALL
                SELECT sender_id as contact_id, MAX(timestamp) as last_time FROM messages WHERE receiver_id = $1 GROUP BY sender_id
            ) t GROUP BY contact_id ORDER BY last_time DESC
        `, [a.userId]);
        const chats = await Promise.all(r.rows.map(async row => {
            const u = await pool.query('SELECT id, username FROM users WHERE id = $1', [row.contact_id]);
            return u.rows[0];
        }));
        res.end(JSON.stringify(chats.filter(Boolean)));
        return;
    }

    if (req.url.startsWith('/api/messages/')) {
        const a = authenticate(req);
        if (!a) { res.writeHead(401); res.end('[]'); return; }
        const otherId = req.url.split('/').pop();
        const r = await pool.query(`
            SELECT m.*, u.username as sender_username FROM messages m
            JOIN users u ON m.sender_id = u.id
            WHERE (m.sender_id = $1 AND m.receiver_id = $2) OR (m.sender_id = $2 AND m.receiver_id = $1)
            ORDER BY m.timestamp ASC
        `, [a.userId, otherId]);
        res.end(JSON.stringify(r.rows));
        return;
    }

    if (req.url.startsWith('/api/poll/')) {
        const a = authenticate(req);
        if (!a) { res.writeHead(401); res.end('[]'); return; }
        const parts = req.url.split('/');
        const otherId = parts[3];
        const lastId = parseInt(parts[4]) || 0;
        const r = await pool.query(`
            SELECT m.*, u.username as sender_username FROM messages m
            JOIN users u ON m.sender_id = u.id
            WHERE ((m.sender_id = $1 AND m.receiver_id = $2) OR (m.sender_id = $2 AND m.receiver_id = $1))
            AND m.id > $3
            ORDER BY m.timestamp ASC
        `, [a.userId, otherId, lastId]);
        res.end(JSON.stringify(r.rows));
        return;
    }

    if (req.url.startsWith('/api/user/')) {
        const a = authenticate(req);
        if (!a) { res.writeHead(401); res.end('{}'); return; }
        const userId = req.url.split('/').pop();
        const r = await pool.query('SELECT id, username FROM users WHERE id = $1', [parseInt(userId)]);
        res.end(JSON.stringify(r.rows[0] || {}));
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

setInterval(() => {
    wss.clients.forEach(ws => {
        if (ws.isAlive === false) { ws.terminate(); return; }
        ws.isAlive = false;
        ws.ping();
    });
}, 30000);

wss.on('connection', (ws) => {
    ws.isAlive = true;
    ws.on('pong', () => { ws.isAlive = true; });
    let uid = null;
    ws.on('message', async (msg) => {
        try {
            const d = JSON.parse(msg);
            if (d.type === 'ping') { ws.send(JSON.stringify({type:'pong'})); return; }
            if (d.type === 'auth') {
                try {
                    uid = jwt.verify(d.token, SECRET_KEY).userId;
                    clients.set(uid, ws);
                } catch(e) { ws.close(); }
                return;
            }
            if (!uid) return;
            if (d.type === 'private_message') {
                const r = await pool.query(
                    'INSERT INTO messages (sender_id, receiver_id, text, type, file_url) VALUES ($1, $2, $3, $4, $5) RETURNING *',
                    [uid, d.receiverId, d.text || '', d.msgType || 'text', d.fileUrl || null]
                );
                const sender = await pool.query('SELECT id, username FROM users WHERE id = $1', [uid]);
                const obj = {
                    type: 'private_message',
                    id: r.rows[0].id,
                    sender_id: uid,
                    receiver_id: Number(d.receiverId),
                    text: d.text || '',
                    msgType: d.msgType || 'text',
                    file_url: d.fileUrl || null,
                    sender_username: sender.rows[0] ? sender.rows[0].username : '',
                    timestamp: r.rows[0].timestamp
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
initDB().then(() => {
    server.listen(PORT, () => console.log(`✅ Сервер запущен на http://localhost:${PORT}`));
});