require('dotenv').config();
// At the top, after require('dotenv')
const requiredEnv = ['DB_HOST', 'DB_PORT', 'DB_USER', 'DB_PASSWORD', 'DB_NAME', 'JWT_SECRET'];
requiredEnv.forEach(key => {
  if (!process.env[key]) {
    console.error(`Missing required env var: ${key}`);
    process.exit(1);
  }
});
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const app = express();
app.set('trust proxy', 1); // Trust first proxy (Render's load balancer)
app.use(helmet());
app.use(cors({
  origin: [
    'https://atielschools.com',
    'http://localhost:3000',
    'https://localhost:3000'
  ],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  optionsSuccessStatus: 200
}));
app.use(express.json());
// ================= RATE LIMITING =================
const rateLimit = require('express-rate-limit');
// General API limiter (optional - for all routes)
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per window
  message: { error: 'Too many requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});
// Stronger protection specifically for login endpoints
const loginLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 10, // 10 attempts per IP → very strict for login
  message: { error: 'Too many login attempts. Try again in 10 minutes.' },
  standardHeaders: true,
  legacyHeaders: false,
});
// Apply global limiter if you want (optional but recommended)
app.use(generalLimiter);
// Apply stronger limiter **only** to login routes
app.use('/api/admin/login', loginLimiter);
app.use('/api/parent/login', loginLimiter);
// Log every incoming request
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.originalUrl}`);
  next();
});
// ================= DATABASE =================
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: parseInt(process.env.DB_PORT || '14671'),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  connectTimeout: 300000,
  ssl: {
    ca: require('fs').readFileSync('./aiven-ca.pem')
  }
});
// Debug pool events
pool.on('connection', (connection) => {
  console.log('[DEBUG] New connection established to Aiven');
});
pool.on('error', (err) => {
  console.error('[POOL ERROR]', err);
});
app.get('/test-db', async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.query('SELECT 1');
    connection.release();
    res.json({ status: 'connected', rows });
  } catch (err) {
    console.error('[TEST-DB ERROR]', err);
    res.status(500).json({ error: err.message, code: err.code });
  }
});
// ================= HELPER =================
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
// ================= PARENT AUTH MIDDLEWARE =================
const verifyParentAccess = async (req, res, next) => {
  const { studentId } = req.params;
  const authHeader = req.headers.authorization;
  let pin;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    pin = authHeader.split(' ')[1];
  }
  if (!studentId || !pin) {
    return res.status(401).json({ error: 'Student ID and PIN required in Authorization header (Bearer <PIN>)' });
  }
  const connection = await pool.getConnection();
  try {
    const [rows] = await connection.query(
      'SELECT pin_hash FROM students WHERE id = ?',
      [studentId]
    );
    if (!rows.length) {
      return res.status(401).json({ error: 'Invalid student ID' });
    }
    const match = await bcrypt.compare(String(pin), rows[0].pin_hash);
    if (!match) {
      return res.status(401).json({ error: 'Invalid PIN' });
    }
    next();
  } catch (err) {
    console.error('Parent auth error:', err);
    res.status(500).json({ error: 'Server error during authentication' });
  } finally {
    connection.release();
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
app.post('/api/admin/login', loginLimiter, async (req, res) => { // ← add stricter limiter
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }
  const connection = await pool.getConnection();
  try {
    const [rows] = await connection.query(
      'SELECT id, username, password_hash, role, school FROM admins WHERE username = ?',
      [username.trim()]
    );
    if (!rows.length) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }
    const user = rows[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }
    // Update last_login
    await connection.query(
      'UPDATE admins SET last_login = NOW() WHERE id = ?',
      [user.id]
    );
    // Create token with all needed info
    const token = jwt.sign(
      { id: rows[0].id, role: rows[0].role }, // ← add role here
      process.env.JWT_SECRET,
      { expiresIn: '8h' }
    );
    res.json({ token });
  } catch (err) {
    logError(err);
    res.status(500).json({ error: 'Server error during login' });
  } finally {
    connection.release();
  }
});
// ================= STUDENTS =================
// Only one version – with role check
app.post('/api/admin/students', verifyAdminToken, async (req, res) => {
  if (req.admin.role !== 'admin' && req.admin.role !== 'superadmin') {
    return res.status(403).json({ error: 'Forbidden: Insufficient permissions' });
  }
  const { name, school, pin, form, subjects = [] } = req.body;
  if (!name || !school || !form || !pin) {
    return res.status(400).json({ error: 'Name, school, form, and pin are required' });
  }
  const trimmedForm = form.trim().replace(/\s+/g, ' ');
  const allowedForms = ['Form 1', 'Form 2', 'Form 3', 'Form 4'];
  if (!allowedForms.includes(trimmedForm)) {
    return res.status(400).json({ error: 'Invalid form. Use Form 1–4 only.' });
  }
  const connection = await pool.getConnection();
  try {
    const studentId = await generateStudentId(school);
    const pinHash = await bcrypt.hash(String(pin), 10);
    // Insert student
    await connection.query(
      'INSERT INTO students (id, name, school, form, pin_hash) VALUES (?, ?, ?, ?, ?)',
      [studentId, name, school, trimmedForm, pinHash]
    );
    // Form 3 & Form 4: save subjects
    if (trimmedForm === 'Form 3' || trimmedForm === 'Form 4') {
      if (!Array.isArray(subjects) || subjects.length === 0) {
        return res.status(400).json({ error: 'Form 3 and Form 4 require at least one subject' });
      }
      const insertPromises = subjects.map(subj =>
        connection.query(
          'INSERT IGNORE INTO student_subjects (student_id, subject) VALUES (?, ?)',
          [studentId, subj.trim().toUpperCase()]
        )
      );
      await Promise.all(insertPromises);
    }
    res.json({ message: 'Student added successfully', studentId });
  } catch (err) {
    console.error('Add student error:', err);
    res.status(500).json({ error: 'Failed to add student', details: err.message });
  } finally {
    connection.release();
  }
});
app.get('/api/admin/students', verifyAdminToken, async (req, res) => {
  const { form, school: querySchool } = req.query;
  const connection = await pool.getConnection();
  try {
    let query = 'SELECT id, name, school, form FROM students WHERE 1';
    const params = [];
    // IMPORTANT: Restrict teachers to their assigned school
    if (req.admin.role === 'teacher' && req.admin.school) {
      query += ' AND school = ?';
      params.push(req.admin.school);
    }
    // Admins can still use ?school= query param if they want to filter
    else if (querySchool && querySchool.trim() !== '') {
      query += ' AND LOWER(school) = LOWER(?)';
      params.push(querySchool.trim());
    }
    if (form && form.trim() !== '') {
      query += ' AND form = ?';
      params.push(form.trim());
    }
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
  if (req.admin.role !== 'admin' && req.admin.role !== 'superadmin') {
    return res.status(403).json({ error: 'Forbidden: Insufficient permissions' });
  }
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
  if (req.admin.role !== 'admin' && req.admin.role !== 'superadmin') {
    return res.status(403).json({ error: 'Forbidden: Insufficient permissions' });
  }
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
// GET all users
app.get('/api/admin/system-users', verifyAdminToken, async (req, res) => {
  if (req.admin.role !== 'admin' && req.admin.role !== 'superadmin') {
    return res.status(403).json({ error: 'Forbidden' });
  }
  const connection = await pool.getConnection();
  try {
    const [rows] = await connection.query(
      'SELECT id, username, role, created_at FROM admins ORDER BY created_at DESC'
    );
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch users' });
  } finally {
    connection.release();
  }
});
// POST - add new user
app.post('/api/admin/system-users', verifyAdminToken, async (req, res) => {
  if (req.admin.role !== 'admin' && req.admin.role !== 'superadmin') {
    return res.status(403).json({ error: 'Forbidden' });
  }
  const { username, password, role } = req.body;
  if (!username || !password || !role) {
    return res.status(400).json({ error: 'Username, password and role required' });
  }
  const connection = await pool.getConnection();
  try {
    const passwordHash = await bcrypt.hash(password, 10);
    await connection.query(
      'INSERT INTO admins (username, password_hash, role) VALUES (?, ?, ?)',
      [username.trim(), passwordHash, role.trim()]
    );
    res.json({ message: 'User added successfully' });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ error: 'Username already exists' });
    }
    console.error(err);
    res.status(500).json({ error: 'Failed to add user' });
  } finally {
    connection.release();
  }
});
// PUT - update user (role or password)
app.put('/api/admin/system-users/:id', verifyAdminToken, async (req, res) => {
  if (req.admin.role !== 'admin' && req.admin.role !== 'superadmin') {
    return res.status(403).json({ error: 'Forbidden' });
  }
  const { id } = req.params;
  const { password, role } = req.body;
  const connection = await pool.getConnection();
  try {
    let query = 'UPDATE admins SET ';
    const params = [];
    if (password) {
      const hash = await bcrypt.hash(password, 10);
      query += 'password_hash = ?, ';
      params.push(hash);
    }
    if (role) {
      query += 'role = ?, ';
      params.push(role.trim());
    }
    if (params.length === 0) return res.status(400).json({ error: 'Nothing to update' });
    query = query.slice(0, -2) + ' WHERE id = ?';
    params.push(id);
    const [result] = await connection.query(query, params);
    if (result.affectedRows === 0) return res.status(404).json({ error: 'User not found' });
    res.json({ message: 'User updated successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update user' });
  } finally {
    connection.release();
  }
});
// DELETE user
app.delete('/api/admin/system-users/:id', verifyAdminToken, async (req, res) => {
  if (req.admin.role !== 'admin' && req.admin.role !== 'superadmin') {
    return res.status(403).json({ error: 'Forbidden' });
  }
  const { id } = req.params;
  // Optional: prevent self-deletion
  if (req.admin.id === parseInt(id)) {
    return res.status(403).json({ error: 'Cannot delete your own account' });
  }
  const connection = await pool.getConnection();
  try {
    const [result] = await connection.query('DELETE FROM admins WHERE id = ?', [id]);
    if (result.affectedRows === 0) return res.status(404).json({ error: 'User not found' });
    res.json({ message: 'User deleted successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to delete user' });
  } finally {
    connection.release();
  }
});
// ================= EXAMS =================
app.post('/api/admin/exams', verifyAdminToken, async (req, res) => {
  if (req.admin.role !== 'admin' && req.admin.role !== 'superadmin') {
    return res.status(403).json({ error: 'Forbidden: Insufficient permissions' });
  }
  const { examType, termNumber, year } = req.body;
  if (!examType || !['midterm', 'endterm'].includes(examType)) {
    return res.status(400).json({ error: "examType must be 'midterm' or 'endterm'" });
  }
  if (!termNumber || ![1, 2, 3].includes(Number(termNumber))) {
    return res.status(400).json({ error: "termNumber must be 1, 2, or 3" });
  }
  if (!year || isNaN(year)) {
    return res.status(400).json({ error: "year is required and must be a number" });
  }
  const name = `${examType === 'midterm' ? 'Mid Term' : 'End Term'} ${termNumber} ${year}`;
  const connection = await pool.getConnection();
  try {
    const [result] = await connection.query(
      'INSERT INTO exams (name, term, year) VALUES (?, ?, ?)',
      [name, termNumber, year]
    );
    res.json({
      message: 'Exam created successfully',
      examId: result.insertId,
      name,
      term: termNumber,
      year
    });
  } catch (err) {
    logError(err);
    res.status(500).json({ error: 'Failed to create exam' });
  } finally {
    connection.release();
  }
});
app.get('/api/admin/exams', verifyAdminToken, async (req, res) => {
  if (req.admin.role !== 'admin' && req.admin.role !== 'superadmin') {
    return res.status(403).json({ error: 'Forbidden: Insufficient permissions' });
  }
  const connection = await pool.getConnection();
  try {
    const [rows] = await connection.query(
      'SELECT * FROM exams ORDER BY year DESC, term ASC, name ASC'
    );
    res.json(rows);
  } catch (err) {
    logError(err);
    res.status(500).json({ error: 'Failed to fetch exams' });
  } finally {
    connection.release();
  }
});
// Publish / unpublish an exam (toggle published status)
app.put('/api/admin/exams/:id/publish', verifyAdminToken, async (req, res) => {
  if (req.admin.role !== 'admin' && req.admin.role !== 'superadmin') {
    return res.status(403).json({ error: 'Forbidden: Insufficient permissions' });
  }
  const { id } = req.params;
  const { published } = req.body;
  if (typeof published !== 'boolean') {
    return res.status(400).json({ error: 'published must be true or false' });
  }
  const connection = await pool.getConnection();
  try {
    const [result] = await connection.query(
      'UPDATE exams SET published = ? WHERE id = ?',
      [published, id]
    );
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Exam not found' });
    }
    res.json({
      message: `Exam ${published ? 'published' : 'unpublished'} successfully`
    });
  } catch (err) {
    logError(err);
    res.status(500).json({ error: 'Failed to update publish status' });
  } finally {
    connection.release();
  }
});
// ================= SUBJECTS =================
app.get('/api/admin/subjects', verifyAdminToken, async (req, res) => {
  if (req.admin.role !== 'admin' && req.admin.role !== 'superadmin') {
    return res.status(403).json({ error: 'Forbidden: Insufficient permissions' });
  }
  const { form } = req.query;
  const subjectsByForm = {
    'Form 1': ['AGR','ENG','BIO','CHEM','MATH','GEO','PHY','CHI','LIF','B/K','HIS','COMP','BUS.'],
    'Form 2': ['AGR','ENG','BIO','CHEM','MATH','GEO','PHY','CHI','HIS','COMP'],
    'Form 3': ['BIO','CHEM','MATH','GEO','PHY','CHI','LIF','HIS','COMP'],
    'Form 4': ['AGR','ENG','BIO','CHEM','MATH','GEO','PHY','CHI','LIF','HIS','COMP']
  };
  res.json(subjectsByForm[form] || []);
});
// ================= GET RESULTS (ADMIN) =================
app.get('/api/admin/results', verifyAdminToken, async (req, res) => {
  if (req.admin.role !== 'admin' && req.admin.role !== 'superadmin') {
    return res.status(403).json({ error: 'Forbidden: Insufficient permissions' });
  }
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
  if (!['admin', 'superadmin', 'teacher'].includes(req.admin.role)) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  const results = req.body;
  console.log('Bulk results request received:', results);
  if (!Array.isArray(results) || results.length === 0) {
    return res.status(400).json({ error: 'No results provided' });
  }
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    const examFormMap = {};
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
      const [studentRow] = await connection.query(
        'SELECT form FROM students WHERE id = ?',
        [student_id]
      );
      if (!studentRow.length) throw new Error(`Student not found: ${student_id}`);
      const form = studentRow[0].form;
      if (!examFormMap[exam_id]) examFormMap[exam_id] = new Set();
      examFormMap[exam_id].add(form);
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
    for (const exId of Object.keys(examFormMap)) {
      await connection.query(
        `UPDATE results SET score = ca + midterm + endterm WHERE exam_id = ?`,
        [exId]
      );
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
            r.average_score = ROUND(t.total / t.subjects_count, 2)
        `,
        [exId, exId]
      );
    }
    await connection.commit();
    // Immediate success response
    res.json({
      message: 'Results saved successfully. Grades, remarks, and positions are being calculated in background.'
    });
    // ────────────────────────────────────────────────
    // Background: calculate grades, remarks, and positions
    // ────────────────────────────────────────────────
    setImmediate(async () => {
      const bgConn = await pool.getConnection();
      try {
        for (const exId of Object.keys(examFormMap)) {
          // Grade & remarks
          await bgConn.query(
            `
            UPDATE results r
            JOIN students s ON r.student_id = s.id
            SET
              r.grade = CASE
                WHEN s.form IN ('Form 1','Form 2') AND r.average_score BETWEEN 90 AND 100 THEN 'A'
                WHEN s.form IN ('Form 1','Form 2') AND r.average_score BETWEEN 70 AND 89 THEN 'B'
                WHEN s.form IN ('Form 1','Form 2') AND r.average_score BETWEEN 60 AND 69 THEN 'C'
                WHEN s.form IN ('Form 1','Form 2') AND r.average_score BETWEEN 45 AND 59 THEN 'D'
                WHEN s.form IN ('Form 1','Form 2') THEN 'F'
                WHEN s.form IN ('Form 3','Form 4') AND r.average_score BETWEEN 90 AND 100 THEN '1'
                WHEN s.form IN ('Form 3','Form 4') AND r.average_score BETWEEN 75 AND 89 THEN '2'
                WHEN s.form IN ('Form 3','Form 4') AND r.average_score BETWEEN 70 AND 74 THEN '3'
                WHEN s.form IN ('Form 3','Form 4') AND r.average_score BETWEEN 65 AND 69 THEN '4'
                WHEN s.form IN ('Form 3','Form 4') AND r.average_score BETWEEN 60 AND 64 THEN '5'
                WHEN s.form IN ('Form 3','Form 4') AND r.average_score BETWEEN 55 AND 59 THEN '6'
                WHEN s.form IN ('Form 3','Form 4') AND r.average_score BETWEEN 50 AND 54 THEN '7'
                WHEN s.form IN ('Form 3','Form 4') AND r.average_score BETWEEN 45 AND 49 THEN '8'
                ELSE '9'
              END,
              r.remarks = CASE
                WHEN s.form IN ('Form 1','Form 2') AND r.average_score BETWEEN 90 AND 100 THEN 'Excellent'
                WHEN s.form IN ('Form 1','Form 2') AND r.average_score BETWEEN 70 AND 89 THEN 'Very Good'
                WHEN s.form IN ('Form 1','Form 2') AND r.average_score BETWEEN 60 AND 69 THEN 'Good'
                WHEN s.form IN ('Form 1','Form 2') AND r.average_score BETWEEN 45 AND 59 THEN 'Average'
                WHEN s.form IN ('Form 1','Form 2') THEN 'Fail'
                WHEN s.form IN ('Form 3','Form 4') AND r.average_score >= 75 THEN 'Distinction'
                WHEN s.form IN ('Form 3','Form 4') AND r.average_score BETWEEN 70 AND 74 THEN 'Strong Credit'
                WHEN s.form IN ('Form 3','Form 4') AND r.average_score BETWEEN 65 AND 69 THEN 'Strong Credit'
                WHEN s.form IN ('Form 3','Form 4') AND r.average_score BETWEEN 60 AND 64 THEN 'Credit'
                WHEN s.form IN ('Form 3','Form 4') AND r.average_score BETWEEN 55 AND 59 THEN 'Credit'
                WHEN s.form IN ('Form 3','Form 4') AND r.average_score BETWEEN 50 AND 54 THEN 'Strong Pass'
                WHEN s.form IN ('Form 3','Form 4') AND r.average_score BETWEEN 45 AND 49 THEN 'Pass'
                ELSE 'Fail'
              END
            WHERE r.exam_id = ?
            `,
            [exId]
          );
          // Ranking per form + school
          const formSchoolPairs = new Set();
          const studentForms = {};
          for (const r of results) {
            const studentId = r.student_id;
            if (!studentForms[studentId]) {
              const [studentRow] = await bgConn.query(
                'SELECT form, school FROM students WHERE id = ?',
                [studentId]
              );
              if (studentRow.length === 0) continue;
              const { form, school } = studentRow[0];
              studentForms[studentId] = { form, school };
              formSchoolPairs.add(`${form}_${school}`);
            }
          }
          for (const pair of formSchoolPairs) {
            const [form, school] = pair.split('_');
            const cleanForm = form.trim();
            const cleanSchool = school.trim();
            console.log(`[BACKGROUND RANKING] Processing ${cleanForm} - ${cleanSchool} for exam ${exId}`);
            await bgConn.query(`SET @pos := 0`);
            await bgConn.query(
              `
              UPDATE results r
              JOIN (
                SELECT
                  r.student_id,
                  (@pos := @pos + 1) AS rank
                FROM results r
                JOIN students s ON r.student_id = s.id
                WHERE r.exam_id = ?
                  AND s.form = ?
                  AND s.school = ?
                GROUP BY r.student_id
                ORDER BY SUM(r.score) DESC
              ) ranked
              ON r.student_id = ranked.student_id
                 AND r.exam_id = ?
              SET r.position = ranked.rank
              `,
              [exId, cleanForm, cleanSchool, exId]
            );
          }
        }
        console.log(`Background grade/position calculation completed for exam(s): ${Object.keys(examFormMap).join(', ')}`);
      } catch (bgErr) {
        console.error('Background grade/position calculation failed:', bgErr);
      } finally {
        bgConn.release();
      }
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
app.get('/api/parent/results/:studentId', verifyParentAccess, async (req, res) => {
  const { studentId } = req.params;
  console.log(`[DEBUG] Fetching results for student: ${studentId}`);
  const connection = await pool.getConnection();
  try {
    const [rows] = await connection.query(
      `
      SELECT
        e.name AS exam_name,
        e.term,
        e.year,
        r.subject,
        r.ca,
        r.midterm,
        r.endterm,
        (r.ca + r.midterm + r.endterm) AS total,
        r.position,
        r.grade,
        r.remarks
      FROM results r
      JOIN exams e ON r.exam_id = e.id
      JOIN student_subjects ss ON r.student_id = ss.student_id AND r.subject = ss.subject
      WHERE r.student_id = ?
      ORDER BY r.year DESC, r.term ASC, e.name ASC
      `,
      [studentId]
    );
    console.log(`[DEBUG] Found ${rows.length} rows for ${studentId}`);
    const data = Array.isArray(rows) ? rows : [];
    if (!data.length) return res.json({ student: { id: studentId }, report: {}, classPosition: '-' });
    const report = {};
    const classPositions = {};
    const examGroups = {};
    rows.forEach(row => {
      const examKey = row.exam_name;
      if (!examGroups[examKey]) examGroups[examKey] = [];
      examGroups[examKey].push(row);
    });
    Object.keys(examGroups).forEach(examKey => {
      const group = examGroups[examKey];
      const firstRow = group[0];
      const form = firstRow.form;
      const school = firstRow.school;
      const storedPosition = group[0].position || '-';
      const uniqueStudents = new Set(group.map(r => r.student_id)).size;
      const total = uniqueStudents > 0 ? uniqueStudents : '-';
      classPositions[examKey] = (storedPosition !== '-' && total !== '-')
        ? `${storedPosition}/${total}`
        : '-';
    });
    rows.forEach(row => {
      const yearKey = String(row.year || 'Unknown');
      const termKey = `Term ${String(row.term || 'Unknown')}`;
      if (!report[yearKey]) report[yearKey] = {};
      if (!report[yearKey][termKey]) report[yearKey][termKey] = {};
      const examKey = String(row.exam_name || 'Unknown').trim();
      if (!report[yearKey][termKey][examKey]) {
        report[yearKey][termKey][examKey] = [];
      }
      const totalScore = Number(row.total) || 0;
      const hasScore = totalScore > 0;
      report[yearKey][termKey][examKey].push({
        subject: String(row.subject || 'Unknown'),
        ca: Number(row.ca) || 0,
        midterm: Number(row.midterm) || 0,
        endterm: Number(row.endterm) || 0,
        total: totalScore,
        position: hasScore ? (row.position || '-') : '-',
        grade: hasScore ? (row.grade || '-') : '-',
        remarks: hasScore ? (row.remarks || '-') : '-'
      });
    });
    const firstExamPosition = Object.values(classPositions)[0] || '-';
    res.json({
      student: { id: studentId },
      classPosition: firstExamPosition,
      report
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch results' });
  } finally {
    connection.release();
  }
});
// ────────────────────────────────────────────────
// Helper for component-specific results (CA, Midterm, Endterm)
// ────────────────────────────────────────────────
async function getResultsByComponent(studentId, component) {
  const scoreColumn = component;
  const connection = await pool.getConnection();
  try {
    console.log(`[DEBUG] Fetching ${component} for ${studentId}`);
    const [rows] = await connection.query(
      `
      SELECT
        e.name AS exam_name,
        e.term,
        e.year,
        r.subject,
        r.${scoreColumn} AS score,
        r.position,
        r.grade,
        r.remarks,
        e.locked,
        s.form
      FROM results r
      JOIN exams e ON r.exam_id = e.id
      JOIN student_subjects ss ON r.student_id = ss.student_id AND r.subject = ss.subject
      JOIN students s ON r.student_id = s.id
      WHERE r.student_id = ?
      ORDER BY e.year DESC, e.term ASC, e.name ASC, r.subject ASC
      `,
      [studentId]
    );
    console.log(`[DEBUG] Found ${rows.length} rows for ${component}`);
    // ... rest of your getResultsByComponent function remains unchanged ...
    // (keeping the full function body as-is, no changes here)
  } catch (err) {
    console.error(`[ERROR] ${component} failed for ${studentId}:`, err.message);
    return { report: {}, classPosition: '-' };
  } finally {
    connection.release();
  }
}
// ────────────────────────────────────────────────
// Component-specific endpoints
// ────────────────────────────────────────────────
app.get('/api/parent/results/:studentId/ca', verifyParentAccess, async (req, res) => {
  try {
    const data = await getResultsByComponent(req.params.studentId, 'ca');
    res.json(data);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to load CA results' });
  }
});
app.get('/api/parent/results/:studentId/midterm', verifyParentAccess, async (req, res) => {
  try {
    const data = await getResultsByComponent(req.params.studentId, 'midterm');
    res.json(data);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to load Midterm results' });
  }
});
app.get('/api/parent/results/:studentId/endterm', verifyParentAccess, async (req, res) => {
  try {
    const data = await getResultsByComponent(req.params.studentId, 'endterm');
    res.json(data);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to load Endterm results' });
  }
});
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok', uptime: process.uptime() });
});
// ================= SERVER =================
const PORT = process.env.PORT;
if (!PORT) {
  console.error('❌ PORT environment variable is not set');
  process.exit(1);
}
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Server running on port ${PORT}`);
  console.log(`Server started at ${new Date().toISOString()} – ready for requests`);
});