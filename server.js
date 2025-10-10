const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3');
const { open } = require('sqlite');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
require('dotenv').config();

const DB_FILE = process.env.DATABASE_FILE || './atiel.db';
const JWT_SECRET = process.env.JWT_SECRET || 'please_change_this_secret';
const PORT = process.env.PORT || 3000;

async function openDb() {
  return open({ filename: DB_FILE, driver: sqlite3.Database });
}

async function verifyAdminToken(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'Missing Authorization header' });
  const parts = auth.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') return res.status(401).json({ error: 'Invalid Authorization format' });
  const token = parts[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.admin = payload;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

async function verifyParentToken(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'Missing Authorization header' });
  const parts = auth.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') return res.status(401).json({ error: 'Invalid Authorization format' });
  const token = parts[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (!payload.studentId) return res.status(401).json({ error: 'Invalid parent token' });
    req.studentId = payload.studentId;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

const app = express();
app.use(helmet());
app.use(cors());
app.use(bodyParser.json());

app.get('/api/ping', (req, res) => res.json({ ok: true, time: new Date() }));

// Admin login
app.post('/api/admin/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });
  const db = await openDb();
  const admin = await db.get('SELECT * FROM admins WHERE username = ?', [username]);
  await db.close();
  if (!admin) return res.status(401).json({ error: 'invalid credentials' });
  const match = await bcrypt.compare(password, admin.password_hash);
  if (!match) return res.status(401).json({ error: 'invalid credentials' });
  const token = jwt.sign({ adminId: admin.id, username: admin.username, role: 'admin' }, JWT_SECRET, { expiresIn: '12h' });
  res.json({ token });
});

// Parent login
app.post('/api/parent/login', async (req, res) => {
  const { studentId, pin } = req.body;
  if (!studentId || !pin) return res.status(400).json({ error: 'studentId and pin required' });
  const db = await openDb();
  const student = await db.get('SELECT id, name, school, form, pin_hash FROM students WHERE id = ?', [studentId]);
  await db.close();
  if (!student) return res.status(404).json({ error: 'student not found' });
  if (!student.pin_hash) return res.status(403).json({ error: 'no PIN set for this student; contact admin' });
  const ok = await bcrypt.compare(String(pin), student.pin_hash);
  if (!ok) return res.status(401).json({ error: 'invalid credentials' });
  const token = jwt.sign({ studentId: student.id, role: 'parent' }, JWT_SECRET, { expiresIn: '6h' });
  res.json({ token, student: { id: student.id, name: student.name, school: student.school, form: student.form } });
});

// Parent fetch own results
app.get('/api/parent/me', verifyParentToken, async (req, res) => {
  const sid = req.studentId;
  const db = await openDb();
  const student = await db.get('SELECT id, name, school, form FROM students WHERE id = ?', [sid]);
  if (!student) { await db.close(); return res.status(404).json({ error: 'student not found' }); }
  const rows = await db.all('SELECT year, term, subject, score FROM results WHERE student_id = ? ORDER BY year DESC', [sid]);
  await db.close();
  const grouped = {};
  for (const r of rows) {
    if (!grouped[r.year]) grouped[r.year] = {};
    if (!grouped[r.year][r.term]) grouped[r.year][r.term] = {};
    grouped[r.year][r.term][r.subject] = r.score;
  }
  res.json({ student, results: grouped });
});

app.listen(PORT, () => {
  console.log(`Atiel backend running on port ${PORT}`);
  console.log('Make sure you ran `npm run init-db` at least once to create the database.');
});