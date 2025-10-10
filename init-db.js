const sqlite3 = require('sqlite3');
const { open } = require('sqlite');
const bcrypt = require('bcrypt');
const fs = require('fs');
require('dotenv').config();

(async () => {
  const DB_FILE = process.env.DATABASE_FILE || './atiel.db';
  if (fs.existsSync(DB_FILE)) fs.unlinkSync(DB_FILE);

  const db = await open({ filename: DB_FILE, driver: sqlite3.Database });

  await db.exec(`
    PRAGMA foreign_keys = ON;
    CREATE TABLE admins (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE students (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      school TEXT NOT NULL,
      form TEXT,
      pin_hash TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE results (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      student_id TEXT NOT NULL,
      year INTEGER NOT NULL,
      term TEXT NOT NULL,
      subject TEXT NOT NULL,
      score INTEGER NOT NULL,
      FOREIGN KEY(student_id) REFERENCES students(id) ON DELETE CASCADE
    );
  `);

  const adminUser = process.env.ADMIN_USERNAME || 'admin';
  const adminPass = process.env.ADMIN_PASSWORD || 'admin123';
  const adminHash = await bcrypt.hash(adminPass, 10);
  await db.run('INSERT INTO admins (username, password_hash) VALUES (?, ?)', [adminUser, adminHash]);

  const sampleStudents = [
    { id: 'AG-1001', name: 'Grace Mwale', school: 'girls', form: 'Form 2', pin: '1111' },
    { id: 'AB-2001', name: 'John Banda', school: 'boys', form: 'Form 3', pin: '2222' }
  ];

  for (const s of sampleStudents) {
    const pinHash = await bcrypt.hash(s.pin, 10);
    await db.run('INSERT INTO students (id, name, school, form, pin_hash) VALUES (?, ?, ?, ?, ?)', [s.id, s.name, s.school, s.form, pinHash]);
  }

  const insertResult = async (studentId, year, term, subject, score) => {
    await db.run('INSERT INTO results (student_id, year, term, subject, score) VALUES (?, ?, ?, ?, ?)', [studentId, year, term, subject, score]);
  };

  await insertResult('AG-1001', 2025, 'term1', 'Math', 78);
  await insertResult('AG-1001', 2025, 'term1', 'English', 85);
  await insertResult('AG-1001', 2025, 'term1', 'Science', 82);

  await insertResult('AB-2001', 2025, 'term1', 'Math', 68);
  await insertResult('AB-2001', 2025, 'term1', 'English', 72);
  await insertResult('AB-2001', 2025, 'term1', 'Physics', 70);

  console.log('Database initialized and seeded with sample data.');
  await db.close();
})();