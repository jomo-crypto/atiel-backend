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

// ======== ADMIN LOGIN ========
app.post('/api/admin/login', async (req, res) => {
  console.log('🟢 Admin login attempt:', req.body);

  const { username, password } = req.body;
  if (!username || !password) {
    console.log('⛔ Missing username or password');
    return res.status(400).json({ error: 'username and password required' });
  }

  try {
    const [rows] = await pool.query('SELECT * FROM admins WHERE username = ?', [username]);
    const admin = rows[0];

    if (!admin) {
      console.log('⛔ No such admin:', username);
      return res.status(401).json({ error: 'invalid credentials' });
    }

    const match = await bcrypt.compare(password, admin.password_hash);
    console.log('Password match result:', match);

    if (!match) {
      console.log('⛔ Wrong password for', username);
      return res.status(401).json({ error: 'invalid credentials' });
    }

    const token = jwt.sign(
      { adminId: admin.id, username: admin.username, role: 'admin' },
      JWT_SECRET,
      { expiresIn: '12h' }
    );
    console.log('✅ Admin login success for', username);
    res.json({ token });

  } catch (err) {
    console.error('Admin login error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ======== ADMIN: ADD STUDENT ========
app.post('/api/admin/students', verifyAdminToken, async (req, res) => {
  const { id, name, school, form, pin } = req.body;
  if (!id || !name || !school || !form || !pin)
    return res.status(400).json({ error: 'All fields required' });

  try {
    const pinHash = await bcrypt.hash(String(pin), 10);
    await pool.query(
      'INSERT INTO students (id, name, school, form, pin_hash) VALUES (?, ?, ?, ?, ?)',
      [id, name, school, form, pinHash]
    );

    res.json({ ok: true, message: 'Student added' });
  } catch (err) {
    console.error('Error adding student:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ======== ADMIN: RESET STUDENT PIN ========
app.put('/api/admin/students/reset-pin', verifyAdminToken, async (req, res) => {
  const { studentId, newPin } = req.body;
  if (!studentId || !newPin) {
    return res.status(400).json({ error: 'studentId and newPin required' });
  }

  try {
    const hashedPin = await bcrypt.hash(String(newPin), 10);
    await pool.query(
      'UPDATE students SET pin_hash = ? WHERE id = ?',
      [hashedPin, studentId]
    );

    res.json({ ok: true, message: `PIN reset for ${studentId}` });
  } catch (err) {
    console.error('Error resetting PIN:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ======== ADMIN: ADD EXAM ========
app.post('/api/admin/exams', verifyAdminToken, async (req, res) => {
  const { name, year, term } = req.body;
  if (!name || !year || !term)
    return res.status(400).json({ error: 'All fields required' });

  try {
    const [result] = await pool.query(
      'INSERT INTO exams (name, year, term) VALUES (?, ?, ?)',
      [name, year, term]
    );

    res.json({ ok: true, examId: result.insertId });
  } catch (err) {
    console.error('Error adding exam:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ======== ADMIN: ADD RESULTS ========
app.post('/api/admin/results', verifyAdminToken, async (req, res) => {
  const { studentId, examId, subject, score } = req.body;
  if (!studentId || !examId || !subject || score == null)
    return res.status(400).json({ error: 'All fields required' });

  try {
    await pool.query(
      'INSERT INTO results (student_id, exam_id, subject, score) VALUES (?, ?, ?, ?)',
      [studentId, examId, subject, score]
    );

    res.json({ ok: true });
  } catch (err) {
    console.error('Error adding result:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ======== PARENT LOGIN ========
app.post('/api/parent/login', async (req, res) => {
  console.log('🟡 Parent login attempt:', req.body);
  const { studentId, pin } = req.body;

  if (!studentId || !pin)
    return res.status(400).json({ error: 'studentId and pin required' });

  try {
    const [rows] = await pool.query('SELECT * FROM students WHERE id = ?', [studentId]);
    const student = rows[0];

    if (!student) {
      console.log('⛔ No such student:', studentId);
      return res.status(401).json({ error: 'invalid credentials' });
    }

    const match = await bcrypt.compare(String(pin), student.pin_hash);
    console.log('Pin match result:', match);

    if (!match) {
      console.log('⛔ Wrong PIN for student', studentId);
      return res.status(401).json({ error: 'invalid credentials' });
    }

    const token = jwt.sign({ studentId: student.id }, JWT_SECRET, { expiresIn: '12h' });
    console.log('✅ Parent login success for', studentId);
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
    const [students] = await pool.query(
      'SELECT id, name, school, form FROM students WHERE id = ?',
      [sid]
    );
    const student = students[0];

    if (!student) return res.status(404).json({ error: 'student not found' });

    const [exams] = await pool.query('SELECT * FROM exams ORDER BY year DESC, term DESC');

    const resultsData = {};
    for (const exam of exams) {
      const [rows] = await pool.query(
        'SELECT student_id, subject, score FROM results WHERE exam_id = ?',
        [exam.id]
      );

      const scoresByStudent = {};
      rows.forEach(r => {
        if (!scoresByStudent[r.student_id]) scoresByStudent[r.student_id] = 0;
        scoresByStudent[r.student_id] += r.score;
      });

      const sorted = Object.entries(scoresByStudent).sort((a, b) => b[1] - a[1]);
      const positions = {};
      sorted.forEach(([studId, total], idx) => (positions[studId] = idx + 1));

      const studentResults = rows
        .filter(r => r.student_id === sid)
        .reduce((acc, r) => {
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

// ======== START SERVER ========
app.listen(PORT, () => {
  console.log(`🚀 Atiel backend running on port ${PORT}`);
});
