console.log('🔥 FULL SERVER.JS LOADED');

require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');

const app = express();
app.use(helmet());
app.use(cors({
  origin: [
    'https://atielschools.com',
    'http://localhost:3000'
  ]
}));
app.use(express.json());

// ================= DATABASE =================
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 100,
  queueLimit: 0
});

// ================= HELPERS =================
const logError = (err) => console.error(new Date().toISOString(), err);

// ================= MIDDLEWARE =================
const verifyAdminToken = (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Unauthorized' });
    req.admin = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// ================= UTILITIES =================
const generateStudentId = async (school) => {
  const prefix = school === 'girls' ? 'AG' : 'AB';
  const connection = await pool.getConnection();
  try {
    const [rows] = await connection.query(
      'SELECT id FROM students WHERE id LIKE ? ORDER BY id DESC LIMIT 1',
      [`${prefix}-%`]
    );
    let next = 1001;
    if (rows.length) next = parseInt(rows[0].id.split('-')[1]) + 1;
    return `${prefix}-${next}`;
  } finally {
    connection.release();
  }
};

// ================= HEALTH CHECK =================
app.get('/', (req, res) => res.json({ message: 'Server OK' }));

// ================= ADMIN AUTH =================
app.post('/api/admin/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: 'Username and password required' });

  const connection = await pool.getConnection();
  try {
    const [rows] = await connection.query(
      'SELECT * FROM admins WHERE username = ?',
      [username]
    );
    if (!rows.length) return res.status(401).json({ error: 'Invalid credentials' });

    const match = await bcrypt.compare(password, rows[0].password_hash);
    if (!match) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ id: rows[0].id }, process.env.JWT_SECRET, { expiresIn: '8h' });
    res.json({ token });
  } catch (err) {
    logError(err);
    res.status(500).json({ error: 'Server error' });
  } finally {
    connection.release();
  }
});

// ================= ADMIN: STUDENTS =================
app.post('/api/admin/students', verifyAdminToken, async (req, res) => {
  const { name, school, form, pin } = req.body;
  if (!name || !school || !form || !pin)
    return res.status(400).json({ error: 'All fields required' });

  const connection = await pool.getConnection();
  try {
    const id = await generateStudentId(school);
    const pinHash = await bcrypt.hash(String(pin), 10);

    await connection.query(
      'INSERT INTO students (id, name, school, form, pin_hash) VALUES (?, ?, ?, ?, ?)',
      [id, name, school, form, pinHash]
    );

    res.json({ message: 'Student added', studentId: id });
  } catch (err) {
    logError(err);
    res.status(500).json({ error: 'Failed to add student' });
  } finally {
    connection.release();
  }
});

app.get('/api/admin/students', verifyAdminToken, async (req, res) => {
  const { form } = req.query;
  const connection = await pool.getConnection();
  try {
    const query = form
      ? 'SELECT id, name, school, form FROM students WHERE form = ? ORDER BY name'
      : 'SELECT id, name, school, form FROM students ORDER BY form, name';

    const [rows] = await connection.query(query, form ? [form] : []);
    res.json(rows);
  } catch (err) {
    logError(err);
    res.status(500).json({ error: 'Failed to fetch students' });
  } finally {
    connection.release();
  }
});

// ================= ADMIN: EXAMS =================
app.post('/api/admin/exams', verifyAdminToken, async (req, res) => {
  const { name, term, year } = req.body;
  if (!name || !term || !year) return res.status(400).json({ error: 'Missing fields' });

  const connection = await pool.getConnection();
  try {
    await connection.query('INSERT INTO exams (name, term, year) VALUES (?, ?, ?)', [name, term, year]);
    res.json({ message: 'Exam created' });
  } catch (err) {
    logError(err);
    res.status(500).json({ error: 'Failed to create exam' });
  } finally {
    connection.release();
  }
});

app.get('/api/admin/exams', verifyAdminToken, async (req, res) => {
  const connection = await pool.getConnection();
  try {
    const [rows] = await connection.query('SELECT * FROM exams ORDER BY year DESC, term ASC');
    res.json(rows);
  } catch (err) {
    logError(err);
    res.status(500).json({ error: 'Failed to fetch exams' });
  } finally {
    connection.release();
  }
});

// ================= ADMIN: RESULTS =================
app.post('/api/admin/results/bulk', verifyAdminToken, async (req, res) => {
  const results = req.body;
  if (!Array.isArray(results) || results.length === 0)
    return res.status(400).json({ error: 'No results provided' });

  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();

    for (const r of results) {
      const { student_id, subject, ca = 0, midterm = 0, endterm = 0, exam_id, term, year } = r;
      if (!student_id || !subject || !exam_id || !term || !year) {
        throw new Error(`Missing fields for ${student_id} ${subject}`);
      }

      const [studentRow] = await connection.query('SELECT form FROM students WHERE id = ?', [student_id]);
      if (!studentRow.length) throw new Error(`Student not found: ${student_id}`);

      await connection.query(
        `INSERT INTO results (student_id, subject, ca, midterm, endterm, exam_id, term, year)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE ca=VALUES(ca), midterm=VALUES(midterm), endterm=VALUES(endterm)`,
        [student_id, subject, ca, midterm, endterm, exam_id, term, year]
      );
    }

    await connection.commit();
    res.json({ message: 'Results saved successfully' });
  } catch (err) {
    await connection.rollback();
    logError(err);
    res.status(500).json({ error: 'Failed to save results', details: err.message });
  } finally {
    connection.release();
  }
});

app.get('/api/admin/results', verifyAdminToken, async (req, res) => {
  const { exam_id, student_id } = req.query;
  const connection = await pool.getConnection();
  try {
    let query = 'SELECT r.*, s.name AS student_name, e.name AS exam_name FROM results r JOIN students s ON r.student_id=s.id JOIN exams e ON r.exam_id=e.id WHERE 1';
    const params = [];
    if (exam_id) { query += ' AND r.exam_id=?'; params.push(exam_id); }
    if (student_id) { query += ' AND r.student_id=?'; params.push(student_id); }

    query += ' ORDER BY s.name, r.subject';
    const [rows] = await connection.query(query, params);
    res.json(rows);
  } catch (err) {
    logError(err);
    res.status(500).json({ error: 'Failed to fetch results' });
  } finally {
    connection.release();
  }
});

// ================= PARENT: LOGIN =================
app.post('/api/parent/login', async (req, res) => {
  const { studentId, pin } = req.body;
  if (!studentId || !pin) return res.status(400).json({ error: 'Student ID and PIN required' });

  const connection = await pool.getConnection();
  try {
    const [rows] = await connection.query('SELECT * FROM students WHERE id=?', [studentId]);
    if (!rows.length) return res.status(401).json({ error: 'Invalid credentials' });

    const student = rows[0];
    const match = await bcrypt.compare(String(pin), student.pin_hash);
    if (!match) return res.status(401).json({ error: 'Invalid credentials' });

    res.json({ id: student.id, name: student.name, form: student.form, school: student.school });
  } catch (err) {
    logError(err);
    res.status(500).json({ error: 'Server error' });
  } finally {
    connection.release();
  }
});

// ================= PARENT: RESULTS =================
app.get('/api/parent/results/:studentId', async (req, res) => {
  const { studentId } = req.params;
  const connection = await pool.getConnection();
  try {
    const [rows] = await connection.query(
      `SELECT r.*, s.name AS student_name, e.name AS exam_name 
       FROM results r 
       JOIN students s ON r.student_id=s.id 
       JOIN exams e ON r.exam_id=e.id 
       WHERE r.student_id=?`,
      [studentId]
    );
    res.json(rows);
  } catch (err) {
    logError(err);
    res.status(500).json({ error: 'Failed to fetch results' });
  } finally {
    connection.release();
  }
});

// ================= SERVER =================
const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => console.log(`✅ Server running on port ${PORT}`));
