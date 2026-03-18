const http = require('http');
const WebSocket = require('ws');
const fs = require('fs');
const path = require('path');

const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const db = new Database('db.sqlite');

// создаём таблицу пользователей
db.prepare(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
  )
`).run();

const SECRET = 'secret123';

const server = http.createServer((req, res) => {
  // регистрация
  if (req.url === '/register' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      const { username, password } = JSON.parse(body);

      const hash = bcrypt.hashSync(password, 8);

      try {
        db.prepare('INSERT INTO users (username, password) VALUES (?, ?)')
          .run(username, hash);

        res.end(JSON.stringify({ success: true }));
      } catch {
        res.end(JSON.stringify({ success: false, error: 'User exists' }));
      }
    });
    return;
  }

  // логин
  if (req.url === '/login' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      const { username, password } = JSON.parse(body);

      const user = db.prepare('SELECT * FROM users WHERE username = ?')
        .get(username);

      if (!user || !bcrypt.compareSync(password, user.password)) {
        res.end(JSON.stringify({ success: false }));
        return;
      }

      const token = jwt.sign({ id: user.id, username }, SECRET);

      res.end(JSON.stringify({ success: true, token }));
    });
    return;
  }

  // отдаём сайт
  const filePath = path.join(__dirname, 'index.html');
  fs.readFile(filePath, (err, data) => {
    if (err) { res.writeHead(404); res.end('Not found'); return; }
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(data);
  });
});

const wss = new WebSocket.Server({ server });

wss.on('connection', (ws) => {
  ws.on('message', (message) => {
    const data = JSON.parse(message);

    wss.clients.forEach(client => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(JSON.stringify(data));
      }
    });
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Сервер запущен на порту ${PORT}`);
});