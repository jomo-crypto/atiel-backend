console.log('🔥 BULK RESULTS ROUTE VERSION LOADED');

require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');

const app = express();

/* ================= MIDDLEWARE ================= */
app.use(helmet());
app.use(cors({
  origin: [
    'https://atielschools.com',
    'http://localhost:3000'
  ]
}));
app.use(express.json());

app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.originalUrl}`);
  next();
});

/* ================= DATABASE ================= */
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 100,
  queueLimit: 0
});

/* ================= HELPERS ================= */
const logError = (err) =>
  console.error(new Date().toISOString(), err);

/* Ensure average_score exists */
(async () => {
  const conn = await pool.getConnection();
  try {
    const [c] = await conn.query(
      `SHOW COLUMNS FROM results LIKE 'average_score'`
    );
    if (!c.length) {
      await conn.query(`
        ALTER TABLE results
        ADD COLUMN average_score DECIMAL(5,2) DEFAULT 0.00
      `);
    }
  } finally {
    conn.release();
  }
})().catch(logError);

/* ================= AUTH ================= */
const verifyAdminToken = (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Unauthorized' });
    req.admin = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
};

/* ================= UTIL ================= */
const generateStudentId = async (school) => {
  const prefix = school === 'girls' ? 'AG' : 'AB';
  const conn = await pool.getConnection();
  try {
    const [r] = await conn.query(
      `SELECT id FROM students WHERE id LIKE ? ORDER BY id DESC LIMIT 1`,
      [`${prefix}-%`]
    );
    let next = 1001;
    if (r.length) next = Number(r[0].id.split('-')[1]) + 1;
    return `${prefix}-${next}`;
  } finally {
    conn.release();
  }
};

/* ================= HEALTH ================= */
app.get('/', (_, res) => res.send('OK'));

/* ================= ADMIN LOGIN ================= */
app.post('/api/admin/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: 'Missing credentials' });

  const conn = await pool.getConnection();
  try {
    const [r] = await conn.query(
      `SELECT * FROM admins WHERE username = ?`,
      [username]
    );
    if (!r.length) return res.status(401).json({ error: 'Invalid credentials' });

    const ok = await bcrypt.compare(password, r[0].password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign(
      { id: r[0].id },
      process.env.JWT_SECRET,
      { expiresIn: '8h' }
    );

    res.json({ token });
  } finally {
    conn.release();
  }
});

/* ================= STUDENTS ================= */
app.post('/api/admin/students', verifyAdminToken, async (req, res) => {
  const { name, school, form, pin } = req.body;
  if (!name || !school || !form || !pin)
    return res.status(400).json({ error: 'All fields required' });

  const conn = await pool.getConnection();
  try {
    const id = await generateStudentId(school);
    const pinHash = await bcrypt.hash(String(pin), 10);

    await conn.query(
      `INSERT INTO students (id, name, school, form, pin_hash)
       VALUES (?, ?, ?, ?, ?)`,
      [id, name, school, form, pinHash]
    );

    /* ✅ FIXED RESPONSE */
    res.json({
      message: 'Student added',
      id,
      studentId: id
    });

  } catch (err) {
    logError(err);
    res.status(500).json({ error: 'Failed to add student' });
  } finally {
    conn.release();
  }
});

app.get('/api/admin/students', verifyAdminToken, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const [rows] = await conn.query(
      `SELECT id, name, school, form FROM students ORDER BY form, name`
    );
    res.json(rows);
  } finally {
    conn.release();
  }
});

/* ================= SUBJECTS (ORDER FIXED) ================= */
app.get('/api/admin/subjects', verifyAdminToken, (req, res) => {
  const subjectsByForm = {
    'Form 1': ['AGR','ENG','BIO','CHEM','MATH','GEO','PHY','CHI','LIF','B/K','HIS','COMP','BUS.'],
    'Form 2': ['AGR','ENG','BIO','CHEM','MATH','GEO','PHY','CHICH','HIS','COMP'],
    'Form 3': ['BIO','CHEM','MATH','GEO','PHY','CHICH','SOC','HIS','COMP'],
    'Form 4': ['AGR','ENG','BIO','CHEM','MATH','GEO','PHY','CHICH','SOC','HIS','COMP']
  };
  res.json(subjectsByForm[req.query.form] || []);
});

/* ================= SERVER ================= */
const PORT = process.env.PORT;
if (!PORT) {
  console.error('❌ PORT not set');
  process.exit(1);
}

app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Server running on port ${PORT}`);
});
