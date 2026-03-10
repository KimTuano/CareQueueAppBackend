const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
require("dotenv").config();

const app = express();
app.use(cors());
app.use(express.json());

// ── Database Connection ─────────────────────────────────────
const db = mysql.createPool({
  host:               process.env.DB_HOST || "127.0.0.1",
  user:               process.env.DB_USER || "root",
  password:           process.env.DB_PASS || "",
  database:           process.env.DB_NAME || "carequeue",
  port:               parseInt(process.env.DB_PORT) || 3306,
  waitForConnections: true,
  connectionLimit:    10,
  connectTimeout:     10000,
});

db.getConnection()
  .then((conn) => {
    console.log("✅ MySQL connected to:", process.env.DB_HOST || "127.0.0.1");
    conn.release();
  })
  .catch((err) => console.error("❌ MySQL connection failed:", err.message));

const JWT_SECRET = process.env.JWT_SECRET || "carequeue_secret_key";
const PORT = process.env.PORT || 3000;

// ── Auth Middleware ─────────────────────────────────────────
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ message: "No token provided." });
  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ message: "Invalid or expired token." });
  }
}

// ══════════════════════════════════════════════════════════
//  HEALTH CHECK
// ══════════════════════════════════════════════════════════
app.get("/", (req, res) => {
  res.json({ message: "CareQueue API is running 🏥" });
});

// ══════════════════════════════════════════════════════════
//  REGISTER — POST /api/register
// ══════════════════════════════════════════════════════════
app.post("/api/register", async (req, res) => {
  const { first_name, last_name, middle_name, gender, date_of_birth, mobile, email, password } = req.body;

  if (!first_name || !last_name || !gender || !date_of_birth || !mobile || !email || !password) {
    return res.status(400).json({ message: "All required fields must be filled." });
  }

  try {
    const [existingEmail] = await db.query("SELECT id FROM patients WHERE email = ?", [email]);
    if (existingEmail.length > 0) return res.status(409).json({ message: "Email already registered." });

    const [existingMobile] = await db.query("SELECT id FROM patients WHERE mobile = ?", [mobile]);
    if (existingMobile.length > 0) return res.status(409).json({ message: "Mobile number already registered." });

    const password_hash = await bcrypt.hash(password, 10);

    const today = new Date().toISOString().slice(0, 10).replace(/-/g, "");
    const rand = Math.floor(1000 + Math.random() * 9000);
    const patient_id = `PAT-${today}-${rand}`;

    await db.query(
      `INSERT INTO patients 
        (patient_id, first_name, last_name, middle_name, gender, date_of_birth, mobile, email, password_hash)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [patient_id, first_name, last_name, middle_name || null, gender, date_of_birth, mobile, email, password_hash]
    );

    return res.status(201).json({ message: "Account created successfully!" });
  } catch (err) {
    console.error("Register error:", err);
    return res.status(500).json({ message: "Server error. Please try again." });
  }
});

// ══════════════════════════════════════════════════════════
//  LOGIN — POST /api/login
// ══════════════════════════════════════════════════════════
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) return res.status(400).json({ message: "Email and password are required." });

  try {
    const [rows] = await db.query("SELECT * FROM patients WHERE email = ?", [email]);
    if (rows.length === 0) return res.status(401).json({ message: "Invalid email or password." });

    const patient = rows[0];
    const isMatch = await bcrypt.compare(password, patient.password_hash);
    if (!isMatch) return res.status(401).json({ message: "Invalid email or password." });

    const token = jwt.sign(
      { id: patient.id, patient_id: patient.patient_id, email: patient.email },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    return res.status(200).json({
      message: "Login successful!",
      token,
      user: {
        id: patient.id,
        patient_id: patient.patient_id,
        first_name: patient.first_name,
        last_name: patient.last_name,
        email: patient.email,
        mobile: patient.mobile,
        gender: patient.gender,
        avatar_url: patient.avatar_url,
      },
    });
  } catch (err) {
    console.error("Login error:", err);
    return res.status(500).json({ message: "Server error. Please try again." });
  }
});

// ══════════════════════════════════════════════════════════
//  GET PROFILE — GET /api/profile (protected)
// ══════════════════════════════════════════════════════════
app.get("/api/profile", authMiddleware, async (req, res) => {
  try {
    const [rows] = await db.query(
      "SELECT id, patient_id, first_name, last_name, middle_name, gender, date_of_birth, mobile, email, avatar_url, created_at FROM patients WHERE id = ?",
      [req.user.id]
    );
    if (rows.length === 0) return res.status(404).json({ message: "User not found." });
    return res.json(rows[0]);
  } catch (err) {
    console.error("Profile error:", err);
    return res.status(500).json({ message: "Server error." });
  }
});

// ══════════════════════════════════════════════════════════
//  GET ALL DOCTORS — GET /api/doctors
// ══════════════════════════════════════════════════════════
app.get("/api/doctors", async (req, res) => {
  try {
    const [rows] = await db.query(`
      SELECT 
        id,
        doctor_id,
        first_name,
        last_name,
        middle_name,
        specialization,
        sub_specialization,
        hospital,
        office,
        mobile,
        email,
        gender,
        years_experience
      FROM doctors
      ORDER BY first_name ASC
    `);
    return res.json(rows);
  } catch (err) {
    console.error("❌ Doctors SQL error:", err.message);
    return res.status(500).json({ message: err.message });
  }
});

// ══════════════════════════════════════════════════════════
//  GET DOCTOR BY ID — GET /api/doctors/:id
// ══════════════════════════════════════════════════════════
app.get("/api/doctors/:id", async (req, res) => {
  try {
    const [rows] = await db.query(`
      SELECT 
        id,
        doctor_id,
        first_name,
        last_name,
        middle_name,
        specialization,
        sub_specialization,
        hospital,
        office,
        mobile,
        email,
        gender,
        years_experience,
        address
      FROM doctors
      WHERE id = ?
    `, [req.params.id]);
    if (rows.length === 0) return res.status(404).json({ message: "Doctor not found." });
    return res.json(rows[0]);
  } catch (err) {
    console.error("❌ Doctor info SQL error:", err.message);
    return res.status(500).json({ message: err.message });
  }
});



// ══════════════════════════════════════════════════════════
//  GET APPOINTMENTS — GET /api/appointments/:userId
//  NOTE: appointments table has no hospital_id column.
//  Hospital name is retrieved from doctors.hospital (text field).
// ══════════════════════════════════════════════════════════
app.get("/api/appointments/:userId", authMiddleware, async (req, res) => {
  try {
    const userId = req.params.userId;
    const [rows] = await db.query(`
      SELECT
        a.*,
        d.first_name   AS doctor_first_name,
        d.last_name    AS doctor_last_name,
        d.specialization,
        d.hospital     AS hospital_name
      FROM appointments a
      LEFT JOIN doctors d ON a.doctor_id = d.id
      WHERE a.patient_user_id = ?
         OR a.patient_id      = ?
      ORDER BY a.appointment_date DESC, a.appointment_time DESC
    `, [userId, userId]);
    return res.json(rows);
  } catch (err) {
    console.error("Appointments error:", err.message);
    return res.status(500).json({ message: "Failed to fetch appointments." });
  }
});

// ══════════════════════════════════════════════════════════
//  GET SPECIALIZATIONS with doctor count — GET /api/specializations
// ══════════════════════════════════════════════════════════
app.get("/api/specializations", async (req, res) => {
  try {
    const [fromDoctors] = await db.query(`SELECT specialization AS name, COUNT(*) AS count FROM doctors WHERE specialization IS NOT NULL AND specialization != "" GROUP BY specialization ORDER BY count DESC`);
    if (fromDoctors.length > 0) return res.json(fromDoctors);
    const [fromTable] = await db.query(`SELECT name, 0 AS count FROM specializations ORDER BY name ASC`);
    return res.json(fromTable);
  } catch (err) {
    console.error("Specializations error:", err.message);
    return res.status(500).json({ message: err.message });
  }
});

// ══════════════════════════════════════════════════════════
//  GET HOSPITALS — GET /api/hospitals
// ══════════════════════════════════════════════════════════
app.get("/api/hospitals", async (req, res) => {
  try {
    const [rows] = await db.query(`SELECT id, name FROM hospitals ORDER BY name ASC`);
    return res.json(rows);
  } catch (err) {
    console.error("❌ Hospitals error:", err.message);
    return res.status(500).json({ message: err.message });
  }
});

// ══════════════════════════════════════════════════════════
//  GET DOCTOR SCHEDULES — GET /api/doctors/:id/schedules
// ══════════════════════════════════════════════════════════
app.get("/api/doctors/:id/schedules", async (req, res) => {
  try {
    const [rows] = await db.query(
      `SELECT * FROM doctor_schedules WHERE doctor_id = ? ORDER BY FIELD(day_of_week,'Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday')`,
      [req.params.id]
    );
    return res.json(rows);
  } catch (err) {
    console.error("❌ Schedules error:", err.message);
    return res.status(500).json({ message: err.message });
  }
});

// ══════════════════════════════════════════════════════════
//  GET AVAILABLE SLOTS — GET /api/doctors/:id/available-slots?date=YYYY-MM-DD
//  Returns time slots from doctor_schedules minus already-booked ones
// ══════════════════════════════════════════════════════════
app.get("/api/doctors/:id/available-slots", async (req, res) => {
  const { date } = req.query;
  if (!date) return res.status(400).json({ message: "date query param required (YYYY-MM-DD)" });

  try {
    // day_of_week: 0=Sun 1=Mon 2=Tue 3=Wed 4=Thu 5=Fri 6=Sat
    const dow = new Date(date + "T00:00:00").getDay();

    // 1. Get all scheduled slots for this doctor on this day-of-week
    const [schedRows] = await db.query(
      `SELECT time_slot FROM doctor_schedules WHERE doctor_id = ? AND day_of_week = ?`,
      [req.params.id, dow]
    );

    if (schedRows.length === 0) {
      return res.json({ available: [] }); // Doctor doesn't work this day
    }

    // 2. Get already-booked (non-cancelled) slots for this doctor on this date
    const [bookedRows] = await db.query(
      `SELECT appointment_time FROM appointments 
       WHERE doctor_id = ? AND appointment_date = ? AND status NOT IN ('cancelled','canceled')`,
      [req.params.id, date]
    );
    const bookedTimes = new Set(bookedRows.map(r => r.appointment_time.substring(0, 5)));

    // 3. Return available = scheduled minus booked
    const available = schedRows
      .map(r => r.time_slot.substring(0, 5)) // "08:00:00" → "08:00"
      .filter(t => !bookedTimes.has(t))
      .sort();

    return res.json({ available });
  } catch (err) {
    console.error("❌ Available slots error:", err.message);
    return res.status(500).json({ message: err.message });
  }
});

// ══════════════════════════════════════════════════════════
//  CREATE APPOINTMENT — POST /api/appointments
//  Called by mobile app to book; shows in admin All Appointments
// ══════════════════════════════════════════════════════════
app.post("/api/appointments", async (req, res) => {
  const {
    appointment_id,
    patient_type,
    last_name, first_name, middle_name, name_extension,
    gender, date_of_birth, age, religion,
    landline, mobile, email,
    patient_user_id,
    doctor, doctor_id,
    appointment_date, appointment_time,
    condition_notes, note,
    status,
  } = req.body;

  if (!appointment_date || !appointment_time || !doctor_id) {
    return res.status(400).json({ message: "appointment_date, appointment_time, and doctor_id are required." });
  }

  try {
    // Auto-generate appointment_id if not provided
    const dateStamp = appointment_date.replace(/-/g, "");
    const rand      = Math.floor(1000 + Math.random() * 9000);
    const apptId    = appointment_id || `AP-${dateStamp}-${rand}`;

    // Get doctor's hospital_id for the admin JOIN
    const [docRows] = await db.query(
      `SELECT d.id, d.hospital, h.id AS hospital_id 
       FROM doctors d
       LEFT JOIN hospitals h ON d.hospital = h.name
       WHERE d.id = ?`,
      [doctor_id]
    );
    const hospitalId = docRows.length > 0 ? (docRows[0].hospital_id ?? null) : null;

    await db.query(
      `INSERT INTO appointments 
        (appointment_id, patient_type,
         last_name, first_name, middle_name, name_extension,
         gender, date_of_birth, age, religion,
         landline, mobile, email,
         patient_user_id, patient_id,
         doctor, doctor_id,
         appointment_date, appointment_time,
         condition_notes, note, status)
       VALUES (?,?, ?,?,?,?, ?,?,?,?, ?,?,?, ?,?, ?,?, ?,?, ?,?,?)`,
      [
        apptId, patient_type || "new",
        last_name, first_name, middle_name || null, name_extension || null,
        gender || null, date_of_birth || null, age || null, religion || null,
        landline || null, mobile || null, email || null,
        patient_user_id || null, patient_user_id || null,
        doctor || null, doctor_id,
        appointment_date, appointment_time,
        condition_notes || null, note || null, status || "waiting",
      ]
    );

    return res.status(201).json({
      message: "Appointment booked successfully!",
      appointment: { appointment_id: apptId, status: "waiting" },
    });
  } catch (err) {
    console.error("❌ Book appointment error:", err.message);
    return res.status(500).json({ message: err.message });
  }
});


// ══════════════════════════════════════════════════════════
//  SAVE PUSH TOKEN — POST /api/push-tokens
// ══════════════════════════════════════════════════════════
app.post("/api/push-tokens", authMiddleware, async (req, res) => {
  const { token, platform } = req.body;
  if (!token) return res.status(400).json({ message: "token required" });
  try {
    // Upsert: one token per user per platform
    await db.query(
      `INSERT INTO push_tokens (user_id, token, platform, created_at, updated_at)
       VALUES (?, ?, ?, NOW(), NOW())
       ON DUPLICATE KEY UPDATE token = VALUES(token), updated_at = NOW()`,
      [req.user.id, token, platform || "android"]
    );
    return res.json({ message: "Push token saved." });
  } catch (err) {
    console.error("Push token error:", err.message);
    return res.status(500).json({ message: err.message });
  }
});

// ══════════════════════════════════════════════════════════
//  GET NOTIFICATIONS — GET /api/notifications/:userId
// ══════════════════════════════════════════════════════════
app.get("/api/notifications/:userId", async (req, res) => {
  try {
    const [rows] = await db.query(
      `SELECT id, title, body, type, appointment_id,
              \`read\` AS is_read, created_at, target_doctor, target_admin
       FROM notifications
       WHERE user_id = ?
       ORDER BY created_at DESC
       LIMIT 50`,
      [req.params.userId]
    );
    return res.json(rows);
  } catch (err) {
    console.error("❌ Notifications SQL error:", err.message);
    return res.status(500).json({ message: err.message });
  }
});

// ══════════════════════════════════════════════════════════
//  UNREAD COUNT — GET /api/notifications/:userId/unread-count
// ══════════════════════════════════════════════════════════
app.get("/api/notifications/:userId/unread-count", async (req, res) => {
  try {
    const [rows] = await db.query(
      "SELECT COUNT(*) as count FROM notifications WHERE user_id = ? AND `read` = 0",
      [req.params.userId]
    );
    return res.json({ count: rows[0].count });
  } catch (err) {
    return res.status(500).json({ message: "Failed to fetch unread count." });
  }
});

// ══════════════════════════════════════════════════════════
//  MARK ONE READ — PUT /api/notifications/:id/read
// ══════════════════════════════════════════════════════════
app.put("/api/notifications/:id/read", async (req, res) => {
  try {
    await db.query("UPDATE notifications SET `read` = 1 WHERE id = ?", [req.params.id]);
    return res.json({ message: "Marked as read." });
  } catch (err) {
    return res.status(500).json({ message: err.message });
  }
});

// ══════════════════════════════════════════════════════════
//  MARK ALL READ — PUT /api/notifications/:userId/read-all
// ══════════════════════════════════════════════════════════
app.put("/api/notifications/:userId/read-all", async (req, res) => {
  try {
    await db.query(
      "UPDATE notifications SET `read` = 1 WHERE user_id = ?",
      [req.params.userId]
    );
    return res.json({ message: "All notifications marked as read." });
  } catch (err) {
    return res.status(500).json({ message: err.message });
  }
});

// ══════════════════════════════════════════════════════════
//  HELPER: Insert notification + send Expo push
//  Called internally when appointment status changes
// ══════════════════════════════════════════════════════════
async function sendNotificationToPatient(patientUserId, type, title, body) {
  try {
    // 1. Save to notifications table
    await db.query(
      `INSERT INTO notifications (user_id, type, title, body, read, created_at)
       VALUES (?, ?, ?, ?, 0, NOW())`,
      [patientUserId, type, title, body]
    );

    // 2. Get push token for this patient
    const [tokens] = await db.query(
      "SELECT token FROM push_tokens WHERE user_id = ? ORDER BY updated_at DESC LIMIT 1",
      [patientUserId]
    );

    if (tokens.length === 0) return; // No push token registered

    // 3. Send via Expo Push API
    await fetch("https://exp.host/--/api/v2/push/send", {
      method:  "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({
        to:    tokens[0].token,
        sound: "default",
        title,
        body,
        data:  { screen: "/navigatingPage/notifications", type },
        badge: 1,
        priority: "high",
      }),
    });

    console.log(`📲 Push sent to patient ${patientUserId}: ${title}`);
  } catch (err) {
    console.error("sendNotificationToPatient error:", err.message);
  }
}

// ══════════════════════════════════════════════════════════
//  UPDATE APPOINTMENT STATUS — PUT /api/appointments/:id/status
//  Called by admin to approve / cancel / complete
//  Automatically sends push notification to patient
// ══════════════════════════════════════════════════════════
app.put("/api/appointments/:id/status", async (req, res) => {
  const { status } = req.body;
  const validStatuses = ["waiting", "approved", "cancelled", "completed", "arrived"];
  if (!validStatuses.includes(status)) {
    return res.status(400).json({ message: `status must be one of: ${validStatuses.join(", ")}` });
  }

  try {
    // Get appointment for notification data
    const [rows] = await db.query(
      `SELECT a.*, a.patient_user_id FROM appointments a WHERE a.id = ?`,
      [req.params.id]
    );
    if (rows.length === 0) return res.status(404).json({ message: "Appointment not found." });

    const appt = rows[0];

    // Update status
    await db.query("UPDATE appointments SET status = ? WHERE id = ?", [status, req.params.id]);

    // Build notification message per status
    const doctorName = appt.doctor || "your doctor";
    const dateStr    = appt.appointment_date
      ? new Date(appt.appointment_date).toLocaleDateString("en-PH", { month: "long", day: "numeric", year: "numeric" })
      : "your scheduled date";

    const notifMap = {
      approved:  {
        type:  "appointment_approved",
        title: "✅ Appointment Approved!",
        body:  `Your appointment with ${doctorName} on ${dateStr} has been approved.`,
      },
      cancelled: {
        type:  "appointment_cancelled",
        title: "❌ Appointment Cancelled",
        body:  `Your appointment with ${doctorName} on ${dateStr} has been cancelled.`,
      },
      completed: {
        type:  "appointment_completed",
        title: "🎉 Appointment Completed",
        body:  `Your appointment with ${doctorName} has been marked as completed. Thank you!`,
      },
      waiting: {
        type:  "appointment_waiting",
        title: "⏳ Appointment Pending",
        body:  `Your appointment with ${doctorName} on ${dateStr} is waiting for approval.`,
      },
      arrived: {
        type:  "appointment_reminder",
        title: "📍 Patient Arrived",
        body:  `Your appointment with ${doctorName} is ready. Please proceed.`,
      },
    };

    const notif = notifMap[status];
    if (notif && appt.patient_user_id) {
      await sendNotificationToPatient(appt.patient_user_id, notif.type, notif.title, notif.body);
    }

    return res.json({ message: `Appointment status updated to ${status}.` });
  } catch (err) {
    console.error("❌ Status update error:", err.message);
    return res.status(500).json({ message: err.message });
  }
});


// ══════════════════════════════════════════════════════════
//  GET PRESCRIPTIONS — GET /api/prescriptions
//  ?appointment_id=<int>  or  ?patient_id=<int>
// ══════════════════════════════════════════════════════════
app.get("/api/prescriptions", authMiddleware, async (req, res) => {
  const { appointment_id, patient_id } = req.query;
  try {
    if (appointment_id) {
      const [rows] = await db.query(
        `SELECT id, medication, dosage, instructions, prescribed_by, prescribed_date, created_at
         FROM prescriptions WHERE appointment_id = ?
         ORDER BY prescribed_date DESC, id DESC`,
        [appointment_id]
      );
      return res.json(rows);
    }
    if (patient_id) {
      const [rows] = await db.query(
        `SELECT id, appointment_id, medication, dosage, instructions, prescribed_by, prescribed_date, created_at
         FROM prescriptions WHERE patient_id = ?
         ORDER BY prescribed_date DESC, id DESC`,
        [patient_id]
      );
      return res.json(rows);
    }
    return res.status(400).json({ message: "appointment_id or patient_id required." });
  } catch (err) {
    console.error("❌ Prescriptions error:", err.message);
    return res.status(500).json({ message: "Failed to fetch prescriptions." });
  }
});

// ── Start Server ────────────────────────────────────────────
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 CareQueue API running on port ${PORT}`);
});