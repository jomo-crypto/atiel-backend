require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
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
  connectionLimit: 10, // adjust safely based on traffic
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
  const connection = await pool.getConnection();
  try {
    const [rows] = await connection.query(
      'SELECT id FROM students WHERE id LIKE ? ORDER BY id DESC LIMIT 1',
      [`${prefix}-%`]
    );
    let next = 1001;
    if (rows.length) {
      next = parseInt(rows[0].id.split('-')[1], 10) + 1;
    }
    return `${prefix}-${next}`;
  } finally {
    connection.release();
  }
};

// ================= ADMIN AUTH =================
app.post('/api/admin/login', async (req, res) => {
  const { username, password } = req.body;
  const connection = await pool.getConnection();
  try {
    const [rows] = await connection.query('SELECT * FROM admins WHERE username = ?', [username]);
    if (!rows.length) return res.status(401).json({ error: 'Invalid credentials' });

    const admin = rows[0];
    const match = await bcrypt.compare(password, admin.password_hash);
    if (!match) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ id: admin.id }, process.env.JWT_SECRET, { expiresIn: '8h' });
    res.json({ token });
  } finally {
    connection.release();
  }
});

// ================= STUDENTS =================
app.post('/api/admin/students', verifyAdminToken, async (req, res) => {
  const { name, school, form, pin } = req.body;
  if (!name || !school || !form || !pin) return res.status(400).json({ error: 'All fields required' });

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
    console.error(err);
    res.status(500).json({ error: 'Error adding student' });
  } finally {
    connection.release();
  }
});

app.get('/api/admin/students', verifyAdminToken, async (req, res) => {
  const connection = await pool.getConnection();
  try {
    const [rows] = await connection.query('SELECT id, name, school, form FROM students ORDER BY name ASC');
    res.json(rows);
  } finally {
    connection.release();
  }
});

// ================= EXAMS =================
app.post('/api/admin/exams', verifyAdminToken, async (req, res) => {
  const { name, term, year } = req.body;
  if (!name || !term || !year) return res.status(400).json({ error: 'Missing fields' });

  const connection = await pool.getConnection();
  try {
    await connection.query(
      'INSERT INTO exams (name, term, year) VALUES (?, ?, ?)',
      [name, term, year]
    );
    res.json({ message: 'Exam created' });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ error: 'Exam for this term and year already exists' });
    }
    console.error(err);
    res.status(500).json({ error: 'Error creating exam' });
  } finally {
    connection.release();
  }
});

app.get('/api/admin/exams', verifyAdminToken, async (req, res) => {
  const connection = await pool.getConnection();
  try {
    const [rows] = await connection.query('SELECT * FROM exams ORDER BY year DESC, term ASC');
    res.json(rows);
  } finally {
    connection.release();
  }
});

// ================= RESULTS =================
app.post('/api/admin/results', verifyAdminToken, async (req, res) => {
  const { student_id, exam_id, subject, ca = 0, midterm = 0, endterm = 0 } = req.body;
  if (!student_id || !exam_id || !subject) return res.status(400).json({ error: 'Missing fields' });

  const connection = await pool.getConnection();
  try {
    await connection.query(
      `
      INSERT INTO results (student_id, exam_id, subject, ca, midterm, endterm)
      VALUES (?, ?, ?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE
        ca = VALUES(ca),
        midterm = VALUES(midterm),
        endterm = VALUES(endterm)
      `,
      [student_id, exam_id, subject, ca, midterm, endterm]
    );
    res.json({ message: 'Result saved' });
  } finally {
    connection.release();
  }
});

app.get('/api/admin/results', verifyAdminToken, async (req, res) => {
  const connection = await pool.getConnection();
  try {
    const [rows] = await connection.query(`
      SELECT 
        r.student_id,
        s.name AS student_name,
        e.id AS exam_id,
        e.name AS exam_name,
        e.term,
        e.year,
        r.subject,
        r.ca,
        r.midterm,
        r.endterm
      FROM results r
      JOIN students s ON s.id = r.student_id
      JOIN exams e ON e.id = r.exam_id
      ORDER BY e.year DESC, e.term ASC, s.name ASC, r.subject ASC
    `);

    // Transform data: group by student + exam
    const grouped = {};
    rows.forEach(r => {
      const key = `${r.student_id}-${r.exam_id}`;
      if (!grouped[key]) {
        grouped[key] = {
          student_id: r.student_id,
          student_name: r.student_name,
          exam_id: r.exam_id,
          exam_name: r.exam_name,
          term: r.term,
          year: r.year,
          subjects: []
        };
      }
      grouped[key].subjects.push({
        subject: r.subject,
        ca: r.ca,
        midterm: r.midterm,
        endterm: r.endterm,
        total: Number(r.ca) + Number(r.midterm) + Number(r.endterm)
      });
    });

    res.json(Object.values(grouped));
  } finally {
    connection.release();
  }
});


// ================= PARENT LOGIN =================
app.post('/api/parent/login', async (req, res) => {
  const { studentId, pin } = req.body;
  const connection = await pool.getConnection();
  try {
    const [rows] = await connection.query('SELECT * FROM students WHERE id = ?', [studentId]);
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
  } finally {
    connection.release();
  }
});

app.get('/api/parent/results/:studentId', async (req, res) => {
  const { studentId } = req.params;
  const connection = await pool.getConnection();
  try {
    const [rows] = await connection.query(`
      SELECT 
        r.subject,
        r.ca,
        r.midterm,
        r.endterm,
        e.term,
        e.year,
        (r.ca + r.midterm + r.endterm) AS total
      FROM results r
      JOIN exams e ON e.id = r.exam_id
      WHERE r.student_id = ?
      ORDER BY e.year DESC, e.term ASC, r.subject ASC
    `, [studentId]);
    res.json(rows);
  } finally {
    connection.release();
  }
});

// ================= SERVER =================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
