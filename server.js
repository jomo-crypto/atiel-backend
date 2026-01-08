console.log('🔥 BULK RESULTS ROUTE VERSION LOADED');

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

// Log every incoming request
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.originalUrl}`);
  next();
});

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

// ================= HELPER =================
const logError = (err) => console.error(new Date().toISOString(), err);

const ensureResultsColumns = async () => {
  const connection = await pool.getConnection();
  try {
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
ensureResultsColumns().catch(logError);

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
app.get('/', (req, res) => res.status(200).send('OK'));

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

    const token = jwt.sign(
      { id: rows[0].id },
      process.env.JWT_SECRET,
      { expiresIn: '8h' }
    );
    res.json({ token });
  } catch (err) {
    logError(err);
    res.status(500).json({ error: 'Server error' });
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

app.delete('/api/admin/students/:id', verifyAdminToken, async (req, res) => {
  const { id } = req.params;
  const connection = await pool.getConnection();
  try {
    await connection.query('DELETE FROM results WHERE student_id = ?', [id]);
    await connection.query('DELETE FROM students WHERE id = ?', [id]);
    res.json({ message: 'Student deleted' });
  } catch (err) {
    logError(err);
    res.status(500).json({ error: 'Failed to delete student' });
  } finally {
    connection.release();
  }
});

app.post('/api/admin/students/:id/regenerate-pin', verifyAdminToken, async (req, res) => {
  const { id } = req.params;
  const newPin = Math.floor(1000 + Math.random() * 9000);
  const connection = await pool.getConnection();
  try {
    const pinHash = await bcrypt.hash(String(newPin), 10);
    await connection.query(
      'UPDATE students SET pin_hash = ? WHERE id = ?',
      [pinHash, id]
    );
    res.json({ message: 'PIN regenerated', newPin });
  } catch (err) {
    logError(err);
    res.status(500).json({ error: 'Failed to regenerate PIN' });
  } finally {
    connection.release();
  }
});

// ================= EXAMS =================
app.post('/api/admin/exams', verifyAdminToken, async (req, res) => {
  const { name, term, year } = req.body;
  if (!name || !term || !year)
    return res.status(400).json({ error: 'Missing fields' });

  const connection = await pool.getConnection();
  try {
    await connection.query(
      'INSERT INTO exams (name, term, year) VALUES (?, ?, ?)',
      [name, term, year]
    );
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
    const [rows] = await connection.query(
      'SELECT * FROM exams ORDER BY year DESC, term ASC'
    );
    res.json(rows);
  } catch (err) {
    logError(err);
    res.status(500).json({ error: 'Failed to fetch exams' });
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

// ================= BULK SAVE RESULTS =================
console.log('🔥 BULK RESULTS ROUTE VERSION LOADED');

app.post('/api/admin/results/bulk', verifyAdminToken, async (req, res) => {
  console.log('Bulk results request received:', req.body);

  if (!Array.isArray(req.body) || req.body.length === 0) {
    return res.status(400).json({ error: 'Invalid or empty payload' });
  }

  const connection = await pool.getConnection();

  try {
    await connection.beginTransaction();

    for (const r of req.body) {
      if (!r.student_id || !r.subject) continue;

      const examId = r.exam_id ? Number(r.exam_id) : null;

      if (!examId) {
        console.warn('⚠️ Skipping row — missing exam_id:', r);
        continue;
      }

      await connection.query(
        `
        INSERT INTO results
          (student_id, subject, ca, midterm, endterm, exam_id, term, year)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON DUPLICATE KEY UPDATE
          ca = VALUES(ca),
          midterm = VALUES(midterm),
          endterm = VALUES(endterm),
          term = VALUES(term),
          year = VALUES(year)
        `,
        [
          r.student_id,
          r.subject,
          Number(r.ca) || 0,
          Number(r.midterm) || 0,
          Number(r.endterm) || 0,
          examId,
          r.term,
          Number(r.year)
        ]
      );
    }

    await connection.commit();
    res.json({ message: 'Results saved successfully' });

  } catch (err) {
    await connection.rollback();
    console.error('❌ BULK RESULTS SQL ERROR:', err);
    res.status(500).json({ error: 'Failed to save results' });

  } finally {
    connection.release();
  }
});


// ================= SERVER =================
const PORT = process.env.PORT;

if (!PORT) {
  console.error('❌ PORT environment variable is not set');
  process.exit(1);
}

app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Server running on port ${PORT}`);
});
