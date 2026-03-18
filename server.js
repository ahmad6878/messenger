const http = require('http');
const WebSocket = require('ws');
const fs = require('fs');
const path = require('path');

const server = http.createServer((req, res) => {
  const filePath = path.join(__dirname, 'index.html');
  fs.readFile(filePath, (err, data) => {
    if (err) { res.writeHead(404); res.end('Not found'); return; }
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(data);
  });
});

const wss = new WebSocket.Server({ server });
const users = {};

wss.on('connection', (ws) => {
  ws.on('message', (message) => {
    const data = JSON.parse(message);
    if (data.type === 'join') {
      ws.username = data.username;
      broadcast({ type: 'system', text: `${data.username} вошёл в чат` });
    }
    if (data.type === 'message') {
      broadcast({ type: 'message', username: ws.username, text: data.text });
    }
  });
  ws.on('close', () => {
    if (ws.username) {
      broadcast({ type: 'system', text: `${ws.username} вышел из чата` });
    }
  });
});

function broadcast(data) {
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify(data));
    }
  });
}

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Сервер запущен на порту ${PORT}`);
});
