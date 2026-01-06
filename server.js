require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(cors({
  origin: ['https://atielschools.com', 'http://localhost:3000']
}));
app.use(express.json());

// ================= DATABASE =================
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10
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

// ================= STUDENTS =================
app.get('/api/admin/students', verifyAdminToken, async (req, res) => {
  const { form } = req.query;
  const connection = await pool.getConnection();
  try {
    const [rows] = await connection.query(
      form
        ? 'SELECT id, name, form FROM students WHERE form = ? ORDER BY name'
        : 'SELECT id, name, form FROM students ORDER BY form, name',
      form ? [form] : []
    );
    res.json(rows);
  } finally {
    connection.release();
  }
});

// ================= EXAMS =================
app.post('/api/admin/exams', verifyAdminToken, async (req, res) => {
  const { name, term, year } = req.body;
  const connection = await pool.getConnection();
  try {
    await connection.query(
      'INSERT INTO exams (name, term, year) VALUES (?, ?, ?)',
      [name, term, year]
    );
    res.json({ message: 'Exam created' });
  } finally {
    connection.release();
  }
});

app.post('/api/admin/exams/:id/lock', verifyAdminToken, async (req, res) => {
  const connection = await pool.getConnection();
  try {
    await connection.query(
      'UPDATE exams SET locked = TRUE WHERE id = ?',
      [req.params.id]
    );
    res.json({ message: 'Results locked' });
  } finally {
    connection.release();
  }
});

// ================= RESULTS (WRITE-PROTECTED) =================
const checkExamUnlocked = async (exam_id) => {
  const [rows] = await pool.query(
    'SELECT locked FROM exams WHERE id = ?',
    [exam_id]
  );
  return rows.length && !rows[0].locked;
};

app.post('/api/admin/results', verifyAdminToken, async (req, res) => {
  const { student_id, exam_id, subject, ca = 0, midterm = 0, endterm = 0 } = req.body;

  if (!(await checkExamUnlocked(exam_id)))
    return res.status(403).json({ error: 'Results locked for this exam' });

  const connection = await pool.getConnection();
  try {
    await connection.query(`
      INSERT INTO results (student_id, exam_id, subject, ca, midterm, endterm)
      VALUES (?, ?, ?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE
        ca = VALUES(ca),
        midterm = VALUES(midterm),
        endterm = VALUES(endterm)
    `, [student_id, exam_id, subject, ca, midterm, endterm]);

    res.json({ message: 'Result saved' });
  } finally {
    connection.release();
  }
});

// ================= REPORT CARD (AVERAGES + POSITIONS) =================
app.get('/api/admin/report-card', verifyAdminToken, async (req, res) => {
  const { form, exam_id } = req.query;
  if (!form || !exam_id)
    return res.status(400).json({ error: 'Missing form or exam_id' });

  const connection = await pool.getConnection();
  try {
    const [rows] = await connection.query(`
      SELECT 
        s.id,
        s.name,
        SUM(r.ca + r.midterm + r.endterm) total,
        AVG(r.ca + r.midterm + r.endterm) average
      FROM students s
      JOIN results r ON r.student_id = s.id
      WHERE s.form = ? AND r.exam_id = ?
      GROUP BY s.id
      ORDER BY total DESC
    `, [form, exam_id]);

    let position = 0;
    let lastTotal = null;

    const ranked = rows.map((r, index) => {
      if (r.total !== lastTotal) position = index + 1;
      lastTotal = r.total;
      return { ...r, position };
    });

    res.json(ranked);
  } finally {
    connection.release();
  }
});

// ================= PARENT RESULTS =================
app.get('/api/parent/results/:studentId', async (req, res) => {
  const connection = await pool.getConnection();
  try {
    const [rows] = await connection.query(`
      SELECT r.subject,
             r.ca, r.midterm, r.endterm,
             (r.ca + r.midterm + r.endterm) total,
             e.term, e.year
      FROM results r
      JOIN exams e ON e.id = r.exam_id
      WHERE r.student_id = ?
      ORDER BY e.year DESC, e.term ASC
    `, [req.params.studentId]);

    res.json(rows);
  } finally {
    connection.release();
  }
});

// ================= SERVER =================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () =>
  console.log(`✅ Server running on port ${PORT}`)
);
