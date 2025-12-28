// ======== IMPORTS & SETUP ========
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
require('dotenv').config();

const pool = require('./db'); // <-- MySQL connection
const JWT_SECRET = process.env.JWT_SECRET || 'please_change_this_secret';
const PORT = process.env.PORT || 5000;

// ======== TOKEN VERIFICATION ========
async function verifyAdminToken(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'Missing Authorization header' });

  const parts = auth.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer')
    return res.status(401).json({ error: 'Invalid Authorization format' });

  try {
    const payload = jwt.verify(parts[1], JWT_SECRET);
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
  if (parts.length !== 2 || parts[0] !== 'Bearer')
    return res.status(401).json({ error: 'Invalid Authorization format' });

  try {
    const payload = jwt.verify(parts[1], JWT_SECRET);
    if (!payload.studentId)
      return res.status(401).json({ error: 'Invalid parent token' });

    req.studentId = payload.studentId;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// ======== EXPRESS APP ========
const app = express();
app.use(helmet());
app.use(cors({
  origin: [
    'https://atielschools.com',
    'http://localhost:3000'
  ],
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));
app.use(bodyParser.json());

// ======== TEST ROUTE ========
app.get('/api/ping', (req, res) => res.json({ ok: true, time: new Date() }));

// ======== AUTO-GENERATE STUDENT ID FUNCTION ========
const generateStudentId = async (school) => {
  const prefix = school === 'girls' ? 'AG' : 'AB';
  const [rows] = await pool.query(
    'SELECT id FROM students WHERE id LIKE ? ORDER BY id DESC LIMIT 1',
    [`${prefix}-%`]
  );
  let nextNumber = 1001; // starting number
  if (rows.length > 0) {
    const lastId = rows[0].id;
    const lastNum = parseInt(lastId.split('-')[1], 10);
    nextNumber = lastNum + 1;
  }
  return `${prefix}-${nextNumber}`;
};

// ======== ADMIN LOGIN ========
app.post('/api/admin/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });

  try {
    const [rows] = await pool.query('SELECT * FROM admins WHERE username = ?', [username]);
    const admin = rows[0];
    if (!admin) return res.status(401).json({ error: 'invalid credentials' });

    const match = await bcrypt.compare(password, admin.password_hash);
    if (!match) return res.status(401).json({ error: 'invalid credentials' });

    const token = jwt.sign({ adminId: admin.id, username: admin.username, role: 'admin' }, JWT_SECRET, { expiresIn: '12h' });
    res.json({ token });
  } catch (err) {
    console.error('Admin login error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ======== ADMIN: ADD STUDENT ========
app.post('/api/admin/students', verifyAdminToken, async (req, res) => {
  const { name, school, form, pin } = req.body;
  if (!name || !school || !form) return res.status(400).json({ error: 'Name, school, and form are required' });

  try {
    const id = await generateStudentId(school); // auto-generate ID
    const studentPin = pin || Math.floor(1000 + Math.random() * 9000).toString(); // auto PIN if not provided
    const pinHash = await bcrypt.hash(String(studentPin), 10);

    await pool.query(
      'INSERT INTO students (id, name, school, form, pin_hash) VALUES (?, ?, ?, ?, ?)',
      [id, name, school, form, pinHash]
    );

    res.json({ ok: true, message: 'Student added', studentId: id, pin: studentPin });
  } catch (err) {
    console.error('Error adding student:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ======== ADMIN: RESET STUDENT PIN ========
app.put('/api/admin/students/reset-pin', verifyAdminToken, async (req, res) => {
  const { studentId, newPin } = req.body;
  if (!studentId || !newPin) return res.status(400).json({ error: 'studentId and newPin required' });

  try {
    const hashedPin = await bcrypt.hash(String(newPin), 10);
    await pool.query('UPDATE students SET pin_hash = ? WHERE id = ?', [hashedPin, studentId]);
    res.json({ ok: true, message: `PIN reset for ${studentId}` });
  } catch (err) {
    console.error('Error resetting PIN:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ======== ADMIN: ADD EXAM ========
app.post('/api/admin/exams', verifyAdminToken, async (req, res) => {
  const { name, year, term } = req.body;
  if (!name || !year || !term) return res.status(400).json({ error: 'All fields required' });

  try {
    const [result] = await pool.query('INSERT INTO exams (name, year, term) VALUES (?, ?, ?)', [name, year, term]);
    res.json({ ok: true, examId: result.insertId });
  } catch (err) {
    console.error('Error adding exam:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ======== ADMIN: ADD RESULTS ========
app.post('/api/admin/results', verifyAdminToken, async (req, res) => {
  const { studentId, examId, subject, score } = req.body;
  if (!studentId || !examId || !subject || score == null) return res.status(400).json({ error: 'All fields required' });

  try {
    await pool.query('INSERT INTO results (student_id, exam_id, subject, score) VALUES (?, ?, ?, ?)', [studentId, examId, subject, score]);
    res.json({ ok: true });
  } catch (err) {
    console.error('Error adding result:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ======== PARENT LOGIN ========
app.post('/api/parent/login', async (req, res) => {
  const { studentId, pin } = req.body;
  if (!studentId || !pin) return res.status(400).json({ error: 'studentId and pin required' });

  try {
    const [rows] = await pool.query('SELECT * FROM students WHERE id = ?', [studentId]);
    const student = rows[0];
    if (!student) return res.status(401).json({ error: 'invalid credentials' });

    const match = await bcrypt.compare(String(pin), student.pin_hash);
    if (!match) return res.status(401).json({ error: 'invalid credentials' });

    const token = jwt.sign({ studentId: student.id }, JWT_SECRET, { expiresIn: '12h' });
    res.json({ token });
  } catch (err) {
    console.error('Parent login error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ======== PARENT: FETCH RESULTS ========
app.get('/api/parent/me', verifyParentToken, async (req, res) => {
  const sid = req.studentId;

  try {
    const [students] = await pool.query('SELECT id, name, school, form FROM students WHERE id = ?', [sid]);
    const student = students[0];
    if (!student) return res.status(404).json({ error: 'student not found' });

    const [exams] = await pool.query('SELECT * FROM exams ORDER BY year DESC, term DESC');

    const resultsData = {};
    for (const exam of exams) {
      const [rows] = await pool.query('SELECT student_id, subject, score FROM results WHERE exam_id = ?', [exam.id]);

      const scoresByStudent = {};
      rows.forEach(r => { scoresByStudent[r.student_id] = (scoresByStudent[r.student_id] || 0) + r.score });

      const sorted = Object.entries(scoresByStudent).sort((a, b) => b[1] - a[1]);
      const positions = {};
      sorted.forEach(([studId], idx) => (positions[studId] = idx + 1));

      const studentResults = rows.filter(r => r.student_id === sid).reduce((acc, r) => {
        acc[r.subject] = r.score;
        return acc;
      }, {});

      resultsData[exam.id] = {
        examName: exam.name,
        year: exam.year,
        term: exam.term,
        subjects: studentResults,
        position: positions[sid],
        totalStudents: sorted.length,
      };
    }

    res.json({ student, results: resultsData });
  } catch (err) {
    console.error('Error fetching parent results:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ======== ADMIN: FETCH ALL STUDENTS (ALPHABETICAL) ========
app.get('/api/admin/students', verifyAdminToken, async (req, res) => {
  try {
    const [students] = await pool.query('SELECT id, name, school, form FROM students ORDER BY name ASC');
    res.json({ ok: true, students });
  } catch (err) {
    console.error('Error fetching students:', err);
    res.status(500).json({ error: err.message });
  }
});

// ======== START SERVER ========
app.listen(PORT, () => {
  console.log(`🚀 Atiel backend running on port ${PORT}`);
});
