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
  connectionLimit: 10,
  queueLimit: 0
});

// ================= ENSURE TOTAL_SCORE & POSITION =================
const ensureResultsColumns = async () => {
  const connection = await pool.getConnection();
  try {
    // Check if columns exist
    const [cols] = await connection.query(`SHOW COLUMNS FROM results LIKE 'total_score'`);
    if (!cols.length) {
      console.log('Adding total_score and position columns...');
      await connection.query(`
        ALTER TABLE results
        ADD COLUMN total_score INT DEFAULT 0,
        ADD COLUMN position INT DEFAULT NULL
      `);
    }
  } finally {
    connection.release();
  }
};

// Call once at startup
ensureResultsColumns().catch(err => console.error('Failed to ensure results columns:', err));

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
    if (rows.length) next = parseInt(rows[0].id.split('-')[1]) + 1;
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
  } finally {
    connection.release();
  }
});

app.delete('/api/admin/students/:id', verifyAdminToken, async (req, res) => {
  const { id } = req.params;
  const connection = await pool.getConnection();
  try {
    await connection.query('DELETE FROM results WHERE student_id = ?', [id]);
    await connection.query('DELETE FROM students WHERE id = ?', [id]);
    res.json({ message: 'Student deleted' });
  } finally {
    connection.release();
  }
});

app.post('/api/admin/students/:id/regenerate-pin', verifyAdminToken, async (req, res) => {
  const { id } = req.params;
  const newPin = Math.floor(1000 + Math.random() * 9000);
  const pinHash = await bcrypt.hash(String(newPin), 10);
  const connection = await pool.getConnection();
  try {
    await connection.query('UPDATE students SET pin_hash = ? WHERE id = ?', [pinHash, id]);
    res.json({ message: 'PIN regenerated', newPin });
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
    await connection.query('INSERT INTO exams (name, term, year) VALUES (?, ?, ?)', [name, term, year]);
    res.json({ message: 'Exam created' });
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

// ================= SUBJECTS =================
app.get('/api/admin/subjects', verifyAdminToken, async (req, res) => {
  const { form } = req.query;
  const subjectsByForm = {
    'Form 1': ['AGR','ENG','BIO','CHEM','MATH','GEO','PHY','CHI','LIF','B/K','HIS','COMP','BUS.'],
    'Form 2': ['AGR','ENG','BIO','CHEM','MATH','GEO','PHY','CHICH','HIS','COMP'],
    'Form 3': ['BIO','CHEM','MATH','GEO','PHY','CHICH','SOC','HIS','COMP'],
    'Form 4': ['AGR','ENG','BIO','CHEM','MATH','GEO','PHY','CHICH','SOC','HIS','COMP']
  };
  res.json(subjectsByForm[form] || []);
});

// ================= RESULTS =================
// Save single result
app.post('/api/admin/results', verifyAdminToken, async (req, res) => {
  const { student_id, exam_id, subject, ca = 0, midterm = 0, endterm = 0, form } = req.body;
  if (!student_id || !exam_id || !subject) return res.status(400).json({ error: 'Missing fields' });

  const connection = await pool.getConnection();
  try {
    // ensure columns exist
    await ensureResultsColumns();

    const [examRows] = await connection.query('SELECT term, year FROM exams WHERE id = ?', [exam_id]);
    const exam = examRows[0];

    const [lockRows] = await connection.query(
      'SELECT * FROM result_locks WHERE form = ? AND term = ? AND year = ?',
      [form, exam.term, exam.year]
    );
    if (lockRows.length) return res.status(403).json({ error: 'Results are locked for this term' });

    await connection.query(
      `INSERT INTO results (student_id, exam_id, subject, ca, midterm, endterm)
       VALUES (?, ?, ?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE
         ca = VALUES(ca),
         midterm = VALUES(midterm),
         endterm = VALUES(endterm)`,
      [student_id, exam_id, subject, ca, midterm, endterm]
    );

    // compute totals & positions
    const [totals] = await connection.query(`
      SELECT student_id, SUM(ca+midterm+endterm) AS total
      FROM results
      WHERE exam_id = ?
      GROUP BY student_id
      ORDER BY total DESC
    `, [exam_id]);

    let position = 1;
    for (let t of totals) {
      await connection.query(
        'UPDATE results SET total_score = ?, position = ? WHERE student_id = ? AND exam_id = ?',
        [t.total, position, t.student_id, exam_id]
      );
      position++;
    }

    res.json({ message: 'Result saved with totals and positions' });
  } finally {
    connection.release();
  }
});

// Bulk save results
app.post('/api/admin/results/bulk', verifyAdminToken, async (req, res) => {
  const results = req.body;
  if (!Array.isArray(results) || results.length === 0) return res.status(400).json({ error: 'No results provided' });

  const connection = await pool.getConnection();
  try {
    await ensureResultsColumns(); // ensure columns exist

    let examId, examTerm, examYear;
    for (let r of results) {
      const { studentId, subject, score, term, year } = r;
      const [examRows] = await connection.query('SELECT id, term, year FROM exams WHERE term = ? AND year = ? LIMIT 1', [term, year]);
      if (examRows.length) {
        examId = examRows[0].id;
        examTerm = examRows[0].term;
        examYear = examRows[0].year;
      } else {
        const [insertRes] = await connection.query(
          'INSERT INTO exams (name, term, year) VALUES (?, ?, ?)',
          [`${term} ${year}`, term, year]
        );
        examId = insertRes.insertId;
        examTerm = term;
        examYear = year;
      }

      const [studentRows] = await connection.query('SELECT form FROM students WHERE id = ?', [studentId]);
      const form = studentRows[0].form;

      const [lockRows] = await connection.query(
        'SELECT * FROM result_locks WHERE form = ? AND term = ? AND year = ?',
        [form, term, year]
      );
      if (lockRows.length) continue;

      await connection.query(
        `INSERT INTO results (student_id, exam_id, subject, ca)
         VALUES (?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE ca = VALUES(ca)`,
        [studentId, examId, subject, score]
      );
    }

    // compute totals & positions
    const [totals] = await connection.query(`
      SELECT student_id, SUM(ca + midterm + endterm) AS total
      FROM results
      WHERE exam_id = ?
      GROUP BY student_id
      ORDER BY total DESC
    `, [examId]);

    let position = 1;
    for (let t of totals) {
      await connection.query(
        'UPDATE results SET total_score = ?, position = ? WHERE student_id = ? AND exam_id = ?',
        [t.total, position, t.student_id, examId]
      );
      position++;
    }

    res.json({ message: 'Bulk results saved with totals and positions' });
  } finally {
    connection.release();
  }
});

// 🔹 UPDATED: Fetch results filtered by form, term, year
app.get('/api/admin/results', verifyAdminToken, async (req, res) => {
  const { form, term, year } = req.query;
  const connection = await pool.getConnection();
  try {
    await ensureResultsColumns();

    let query = `
      SELECT r.student_id, s.name, s.form,
             e.id exam_id, e.name exam_name, e.term, e.year,
             r.subject, r.ca, r.midterm, r.endterm,
             r.total_score, r.position
      FROM results r
      JOIN students s ON s.id = r.student_id
      JOIN exams e ON e.id = r.exam_id
    `;
    const params = [];

    if (form || term || year) {
      query += ' WHERE 1=1';
      if (form) { query += ' AND s.form = ?'; params.push(form); }
      if (term) { query += ' AND e.term = ?'; params.push(term); }
      if (year) { query += ' AND e.year = ?'; params.push(year); }
    }

    query += ' ORDER BY s.name, r.total_score DESC';
    const [rows] = await connection.query(query, params);
    res.json(rows);
  } finally {
    connection.release();
  }
});

// ================= PARENT =================
app.post('/api/parent/login', async (req, res) => {
  const { studentId, pin } = req.body;
  const connection = await pool.getConnection();
  try {
    const [rows] = await connection.query('SELECT * FROM students WHERE id = ?', [studentId]);
    if (!rows.length) return res.status(401).json({ error: 'Invalid login' });
    const student = rows[0];
    const match = await bcrypt.compare(String(pin), student.pin_hash);
    if (!match) return res.status(401).json({ error: 'Invalid login' });
    res.json({ id: student.id, name: student.name, form: student.form, school: student.school });
  } finally {
    connection.release();
  }
});

app.get('/api/parent/results/:studentId', async (req, res) => {
  const connection = await pool.getConnection();
  try {
    await ensureResultsColumns();

    const [rows] = await connection.query(`
      SELECT r.subject, r.ca, r.midterm, r.endterm,
             e.term, e.year,
             r.total_score AS total
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
