const pool = require('./db');
const bcrypt = require('bcrypt');
require('dotenv').config();

(async () => {
  try {
    // ======== DROP TABLES IF THEY EXIST ========
    await pool.query('SET FOREIGN_KEY_CHECKS = 0');
    await pool.query('DROP TABLE IF EXISTS results');
    await pool.query('DROP TABLE IF EXISTS exams');
    await pool.query('DROP TABLE IF EXISTS students');
    await pool.query('DROP TABLE IF EXISTS admins');
    await pool.query('SET FOREIGN_KEY_CHECKS = 1');

    // ======== CREATE TABLES ========
    await pool.query(`
      CREATE TABLE admins (
        id INT PRIMARY KEY AUTO_INCREMENT,
        username VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`
      CREATE TABLE students (
        id VARCHAR(50) PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        school VARCHAR(100) NOT NULL,
        form VARCHAR(50),
        pin_hash VARCHAR(255),
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`
      CREATE TABLE exams (
        id INT PRIMARY KEY AUTO_INCREMENT,
        name VARCHAR(255) NOT NULL,
        year INT NOT NULL,
        term VARCHAR(50) NOT NULL
      )
    `);

    await pool.query(`
      CREATE TABLE results (
        id INT PRIMARY KEY AUTO_INCREMENT,
        student_id VARCHAR(50) NOT NULL,
        exam_id INT NOT NULL,
        subject VARCHAR(100) NOT NULL,
        score INT NOT NULL,
        FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE,
        FOREIGN KEY (exam_id) REFERENCES exams(id) ON DELETE CASCADE
      )
    `);

    // ======== INSERT ADMIN ========
    const adminUser = process.env.ADMIN_USERNAME || 'admin';
    const adminPass = process.env.ADMIN_PASSWORD || 'admin123';
    const adminHash = await bcrypt.hash(adminPass, 10);
    await pool.query(
      'INSERT INTO admins (username, password_hash) VALUES (?, ?)',
      [adminUser, adminHash]
    );

    // ======== INSERT SAMPLE STUDENTS ========
    const sampleStudents = [
      { id: 'AG-1001', name: 'Grace Mwale', school: 'girls', form: 'Form 2', pin: '1111' },
      { id: 'AB-2001', name: 'John Banda', school: 'boys', form: 'Form 3', pin: '2222' }
    ];

    for (const s of sampleStudents) {
      const pinHash = await bcrypt.hash(s.pin, 10);
      await pool.query(
        'INSERT INTO students (id, name, school, form, pin_hash) VALUES (?, ?, ?, ?, ?)',
        [s.id, s.name, s.school, s.form, pinHash]
      );
    }

    // ======== INSERT SAMPLE EXAM ========
    const [examResult] = await pool.query(
      'INSERT INTO exams (name, year, term) VALUES (?, ?, ?)',
      ['Midterm Term 1', 2025, 'term1']
    );
    const examId = examResult.insertId;

    // ======== INSERT SAMPLE RESULTS ========
    const insertResult = async (studentId, subject, score) => {
      await pool.query(
        'INSERT INTO results (student_id, exam_id, subject, score) VALUES (?, ?, ?, ?)',
        [studentId, examId, subject, score]
      );
    };

    await insertResult('AG-1001', 'Math', 78);
    await insertResult('AG-1001', 'English', 85);
    await insertResult('AG-1001', 'Science', 82);

    await insertResult('AB-2001', 'Math', 68);
    await insertResult('AB-2001', 'English', 72);
    await insertResult('AB-2001', 'Physics', 70);

    console.log('✅ MySQL database initialized and ready for multiple schools, exams, and results.');

  } catch (err) {
    console.error('❌ Error initializing MySQL database:', err);
  } finally {
    pool.end();
  }
})();
