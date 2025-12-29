require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

// ================= DATABASE =================
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// ================= MIDDLEWARE =================
const verifyAdminToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  try {
    req.admin = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// ================= UTILITIES =================
const generateStudentId = async (school) => {
  const prefix = school === 'girls' ? 'AG' : 'AB';

  const [rows] = await pool.query(
    'SELECT id FROM students WHERE id LIKE ? ORDER BY id DESC LIMIT 1',
    [`${prefix}-%`]
  );

  let next = 1001;
  if (rows.length) {
    next = parseInt(rows[0].id.split('-')[1], 10) + 1;
  }
  return `${prefix}-${next}`;
};

// ================= ADMIN AUTH =================
app.post('/api/admin/login', async (req, res) => {
  const { username, password } = req.body;
  const [rows] = await pool.query('SELECT * FROM admins WHERE username = ?', [username]);
  if (!rows.length) return res.status(401).json({ error: 'Invalid credentials' });

  const admin = rows[0];
  const match = await bcrypt.compare(password, admin.password_hash);
  if (!match) return res.status(401).json({ error: 'Invalid credentials' });

  const token = jwt.sign({ id: admin.id }, process.env.JWT_SECRET, { expiresIn: '8h' });
  res.json({ token });
});

// ================= STUDENTS =================
app.post('/api/admin/students', verifyAdminToken, async (req, res) => {
  const { name, school, form, pin } = req.body;
  if (!name || !school || !form || !pin) return res.status(400).json({ error: 'All fields required' });

  try {
    const id = await generateStudentId(school);
    const pinHash = await bcrypt.hash(String(pin), 10);
    await pool.query(
      'INSERT INTO students (id, name, school, form, pin_hash) VALUES (?, ?, ?, ?, ?)',
      [id, name, school, form, pinHash]
    );
    res.json({ message: 'Student added', studentId: id });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error adding student' });
  }
});

app.get('/api/admin/students', verifyAdminToken, async (req, res) => {
  const [rows] = await pool.query('SELECT id, name, school, form FROM students ORDER BY name ASC');
  res.json(rows);
});

// ================= EXAMS =================
app.post('/api/admin/exams', verifyAdminToken, async (req, res) => {
  const { name, term, year } = req.body;
  await pool.query('INSERT INTO exams (name, term, year) VALUES (?, ?, ?)', [name, term, year]);
  res.json({ message: 'Exam created' });
});

app.get('/api/admin/exams', verifyAdminToken, async (req, res) => {
  const [rows] = await pool.query('SELECT * FROM exams ORDER BY year DESC, term ASC');
  res.json(rows);
});

// ================= RESULTS =================
app.post('/api/admin/results', verifyAdminToken, async (req, res) => {
  const { student_id, exam_id, subject, ca = 0, midterm = 0, endterm = 0, term = 1 } = req.body;
  if (!student_id || !exam_id || !subject) return res.status(400).json({ error: 'Missing fields' });

  try {
    await pool.query(
      `
      INSERT INTO results (student_id, exam_id, subject, ca, midterm, endterm, term)
      VALUES (?, ?, ?, ?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE
        ca = VALUES(ca),
        midterm = VALUES(midterm),
        endterm = VALUES(endterm),
        term = VALUES(term)
      `,
      [student_id, exam_id, subject, ca, midterm, endterm, term]
    );
    res.json({ message: 'Result saved' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error saving result' });
  }
});

app.get('/api/admin/results', verifyAdminToken, async (req, res) => {
  const { student_id, exam_id } = req.query;
  let sql = `
    SELECT r.*, s.name AS student_name, e.name AS exam_name, e.year, e.term AS exam_term
    FROM results r
    JOIN students s ON s.id = r.student_id
    JOIN exams e ON e.id = r.exam_id
    WHERE 1=1
  `;
  const params = [];
  if (student_id) { sql += ' AND r.student_id = ?'; params.push(student_id); }
  if (exam_id) { sql += ' AND r.exam_id = ?'; params.push(exam_id); }
  sql += ' ORDER BY s.name ASC, r.subject ASC';
  const [rows] = await pool.query(sql, params);
  res.json(rows);
});

// ================= PARENT LOGIN =================
app.post('/api/parent/login', async (req, res) => {
  const { studentId, pin } = req.body;
  const [rows] = await pool.query('SELECT * FROM students WHERE id = ?', [studentId]);
  if (!rows.length) return res.status(401).json({ error: 'Invalid login' });

  const student = rows[0];
  const match = await bcrypt.compare(String(pin), student.pin_hash);
  if (!match) return res.status(401).json({ error: 'Invalid login' });

  res.json({
    id: student.id,
    name: student.name,
    form: student.form,
    school: student.school
  });
});

// ================= SERVER =================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
