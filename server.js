
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
  const { name, school, pin } = req.body;
  let { form } = req.body;

  if (!name || !school || !form || !pin) {
    return res.status(400).json({ error: 'All fields required' });
  }

  // normalize form input
  form = form.trim().replace(/\s+/g, ' ');

  const allowedForms = ['Form 1', 'Form 2', 'Form 3', 'Form 4'];
  if (!allowedForms.includes(form)) {
    return res.status(400).json({ error: 'Invalid form. Use Form 1–4 only.' });
  }

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
  const { form, school } = req.query;
  const connection = await pool.getConnection();

  try {
    // Base query
    let query = 'SELECT id, name, school, form FROM students WHERE 1';
    const params = [];

    // Filter by form if provided
    if (form && form.trim() !== '') {
      query += ' AND form = ?';
      params.push(form.trim());
    }

    // Filter by school if provided (case-insensitive)
    if (school && school.trim() !== '') {
      query += ' AND LOWER(school) = LOWER(?)';
      params.push(school.trim());
    }

    // Order by name
    query += ' ORDER BY name';

    console.log('STUDENTS SQL:', query, params);

    const [rows] = await connection.query(query, params);
    res.json(rows);
  } catch (err) {
    console.error('Failed to fetch students:', err);
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

/// ================= GET RESULTS =================
app.get('/api/admin/results', verifyAdminToken, async (req, res) => {
  const { form, term, year } = req.query;
  const connection = await pool.getConnection();
  try {
    let query = `
      SELECT r.*, s.name AS student_name, e.name AS exam_name, e.locked
      FROM results r
      JOIN students s ON r.student_id = s.id
      JOIN exams e ON r.exam_id = e.id
      WHERE 1
    `;
    const params = [];

    if (form) {
      query += ' AND s.form = ?';
      params.push(form);
    }
    if (term) {
      query += ' AND r.term = ?';
      params.push(term);
    }
    if (year) {
      query += ' AND r.year = ?';
      params.push(year);
    }

    const [rows] = await connection.query(query, params);
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch results' });
  } finally {
    connection.release();
  }
});





// ================= BULK RESULTS (UPSERT + FULL CALCULATION) =================
console.log('🔥 BULK RESULTS ROUTE VERSION LOADED');

app.post('/api/admin/results/bulk', verifyAdminToken, async (req, res) => {
  const results = req.body;

  console.log('Bulk results request received:', results);

  if (!Array.isArray(results) || results.length === 0) {
    return res.status(400).json({ error: 'No results provided' });
  }

  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();

    const examFormMap = {}; // { exam_id: Set of forms }

    // ================= UPSERT =================
    for (const r of results) {
      const {
        student_id,
        subject,
        ca = 0,
        midterm = 0,
        endterm = 0,
        exam_id,
        term,
        year
      } = r;

      if (!student_id || !subject || !exam_id || !term || !year) {
        throw new Error(`Missing required fields for ${student_id} ${subject}`);
      }

      // Get student form
      const [studentRow] = await connection.query(
        'SELECT form FROM students WHERE id = ?',
        [student_id]
      );
      if (!studentRow.length) throw new Error(`Student not found: ${student_id}`);
      const form = studentRow[0].form;

      if (!examFormMap[exam_id]) examFormMap[exam_id] = new Set();
      examFormMap[exam_id].add(form);

      // UPSERT
      await connection.query(
        `
        INSERT INTO results
          (student_id, subject, ca, midterm, endterm, exam_id, term, year)
        VALUES
          (?, ?, ?, ?, ?, ?, ?, ?)
        ON DUPLICATE KEY UPDATE
          ca = VALUES(ca),
          midterm = VALUES(midterm),
          endterm = VALUES(endterm),
          term = VALUES(term),
          year = VALUES(year)
        `,
        [student_id, subject, ca, midterm, endterm, exam_id, term, year]
      );
    }

    // ================= CALCULATE SCORE, TOTAL_SCORE, AVERAGE, GRADE & POSITIONS =================
    for (const exId of Object.keys(examFormMap)) {
      // 1️⃣ score per subject
      await connection.query(
        `UPDATE results SET score = ca + midterm + endterm WHERE exam_id = ?`,
        [exId]
      );

      // 2️⃣ total_score per student
      await connection.query(
        `
        UPDATE results r
        JOIN (
          SELECT student_id, SUM(score) AS total, COUNT(*) AS subjects_count
          FROM results
          WHERE exam_id = ?
          GROUP BY student_id
        ) t
        ON r.student_id = t.student_id AND r.exam_id = ?
        SET r.total_score = t.total,
            r.average_score = t.total / t.subjects_count
        `,
        [exId, exId]
      );

      // 3️⃣ assign grade based on average_score
      await connection.query(
        `
        UPDATE results
        SET grade = CASE
          WHEN average_score >= 80 THEN 'A'
          WHEN average_score >= 70 THEN 'B'
          WHEN average_score >= 60 THEN 'C'
          WHEN average_score >= 50 THEN 'D'
          ELSE 'F'
        END
        WHERE exam_id = ?
        `,
        [exId]
      );

      // 4️⃣ positions per form
      for (const form of examFormMap[exId]) {
        await connection.query(`SET @pos := 0`);
        await connection.query(
          `
          UPDATE results r
          JOIN (
            SELECT r.student_id, (@pos := @pos + 1) AS rank
            FROM results r
            JOIN students s ON r.student_id = s.id
            WHERE r.exam_id = ? AND s.form = ?
            GROUP BY r.student_id
            ORDER BY SUM(r.score) DESC
          ) ranked
          ON r.student_id = ranked.student_id AND r.exam_id = ?
          SET r.position = ranked.rank
          `,
          [exId, form, exId]
        );
      }
    }

    await connection.commit();
    res.json({
      message: 'Results saved successfully with score, total_score, average_score, grade, and position calculated'
    });

  } catch (err) {
    await connection.rollback();
    logError(err);
    res.status(500).json({
      error: 'Failed to save results',
      details: err.message
    });
  } finally {
    connection.release();
  }
});

// ================= PARENT LOGIN =================
app.post('/api/parent/login', async (req, res) => {
  const { studentId, pin } = req.body;

  if (!studentId || !pin) {
    return res.status(400).json({ error: 'Student ID and PIN required' });
  }

  const connection = await pool.getConnection();
  try {
    const [rows] = await connection.query(
      'SELECT id, name, school, form, pin_hash FROM students WHERE id = ?',
      [studentId]
    );

    if (!rows.length) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const student = rows[0];
    const match = await bcrypt.compare(String(pin), student.pin_hash);

    if (!match) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // ✅ Send student info (NO PIN)
    res.json({
      id: student.id,
      name: student.name,
      school: student.school,
      form: student.form
    });

  } catch (err) {
    logError(err);
    res.status(500).json({ error: 'Server error' });
  } finally {
    connection.release();
  }
});


// ================= PARENT RESULTS =================
app.get('/api/parent/results/:studentId', async (req, res) => {
  const { studentId } = req.params;
  const connection = await pool.getConnection();

  try {
    const [rows] = await connection.query(
  `
  SELECT 
    e.name AS exam_name,
    r.term,
    r.year,
    r.subject,
    r.ca,
    r.midterm,
    r.endterm,
    (r.ca + r.midterm + r.endterm) AS total,
    r.position,
    (
      SELECT COUNT(DISTINCT r2.student_id)
      FROM results r2
      WHERE r2.exam_id = r.exam_id
    ) AS totalStudents
  FROM results r
  JOIN exams e ON r.exam_id = e.id
  WHERE r.student_id = ?
  ORDER BY r.year DESC, r.term DESC
  `,
  [studentId]
);


    // 🔄 Transform to match frontend structure
    const examsMap = {};

    for (const row of rows) {
      const key = `${row.exam_name}_${row.term}_${row.year}`;

      if (!examsMap[key]) {
        examsMap[key] = {
          exam_name: row.exam_name,
          term: row.term,
          year: row.year,
          position: row.position,
          totalStudents: row.totalStudents,
          subjects: []
        };
      }

      examsMap[key].subjects.push({
		subject: row.subject,
		ca: row.ca || 0,
		midterm: row.midterm || 0,
		endterm: row.endterm || 0,
		total: row.total,
		position: row.position || '-'
});

    }

    res.json(Object.values(examsMap));

  } catch (err) {
    logError(err);
    res.status(500).json({ error: 'Failed to fetch results' });
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
