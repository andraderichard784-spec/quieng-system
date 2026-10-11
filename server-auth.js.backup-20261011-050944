"use strict";

const express = require("express");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const app = express();
const PORT = Number(process.env.AUTH_PORT || 3000);
const HOST = process.env.AUTH_HOST || "127.0.0.1";
const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, "data");
const DB_FILE = path.join(DATA_DIR, "queueflow-auth-db.json");

const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "QueueFlow@123";
const passwordResetCodes = new Map();

const sessions = new Map();
const SESSION_DURATION = 12 * 60 * 60 * 1000;

const FLOOR_NAMES = {
  G: "Ground Floor",
  "2": "2nd Floor",
  "3": "3rd Floor"
};

app.disable("x-powered-by");
app.use(express.json({ limit: "100kb" }));

function createEmptyDb() {
  return {
    admins: [],
    tellers: [],
    services: [],
    tickets: [],
    nextNumbers: { G: 1, "2": 1, "3": 1 }
  };
}

fs.mkdirSync(DATA_DIR, { recursive: true });

if (!fs.existsSync(DB_FILE)) {
  fs.writeFileSync(DB_FILE, JSON.stringify(createEmptyDb(), null, 2));
}

function loadDb() {
  const db = JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
  if (!db || typeof db !== "object") throw new Error("Invalid database file.");

  if (!Array.isArray(db.tellers)) db.tellers = [];
  if (!Array.isArray(db.services)) db.services = [];
  if (!Array.isArray(db.tickets)) db.tickets = [];
  if (!Array.isArray(db.admins)) db.admins = [];
  if (!db.nextNumbers || typeof db.nextNumbers !== "object") {
    db.nextNumbers = { G: 1, "2": 1, "3": 1 };
  }

  for (const floor of Object.keys(FLOOR_NAMES)) {
    const n = Number(db.nextNumbers[floor]);
    db.nextNumbers[floor] = Number.isInteger(n) && n > 0 ? n : 1;
  }

  return db;
}

let db = loadDb();

function saveDb() {
  const tempFile = DB_FILE + ".tmp";
  fs.writeFileSync(tempFile, JSON.stringify(db, null, 2), "utf8");
  fs.renameSync(tempFile, DB_FILE);
}

function sendError(res, status, message) {
  return res.status(status).json({ error: message });
}

function normalizeFloor(value) {
  const floor = String(value ?? "").trim().toLowerCase();
  if (["g", "ground", "ground floor"].includes(floor)) return "G";
  if (["2", "2nd", "second", "2nd floor"].includes(floor)) return "2";
  if (["3", "3rd", "third", "3rd floor"].includes(floor)) return "3";
  return "";
}

function safeTeller(teller) {
  const { accessCodeSalt, accessCodeHash, ...safe } = teller;
  return safe;
}

function hashAccessCode(code, saltHex) {
  const salt = Buffer.from(saltHex, "hex");
  return crypto.scryptSync(code, salt, 64).toString("hex");
}

function accessCodeMatches(code, teller) {
  try {
    const actual = Buffer.from(
      hashAccessCode(code, teller.accessCodeSalt),
      "hex"
    );
    const expected = Buffer.from(teller.accessCodeHash, "hex");
    return actual.length === expected.length &&
      crypto.timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}


function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function hashAdminPassword(password, saltHex) {
  return crypto.scryptSync(password, Buffer.from(saltHex, "hex"), 64).toString("hex");
}

function adminPasswordMatches(password, admin) {
  try {
    const actual = Buffer.from(hashAdminPassword(password, admin.passwordSalt), "hex");
    const expected = Buffer.from(admin.passwordHash, "hex");
    return actual.length === expected.length &&
      crypto.timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

function ensureDefaultAdmin() {
  const exists = db.admins.some(a =>
    String(a.username).toLowerCase() === ADMIN_USERNAME.toLowerCase()
  );
  if (!exists) {
    const salt = crypto.randomBytes(16).toString("hex");
    db.admins.push({
      id: createId(),
      username: ADMIN_USERNAME,
      email: "admin@queueflow.local",
      passwordSalt: salt,
      passwordHash: hashAdminPassword(ADMIN_PASSWORD, salt),
      createdAt: new Date().toISOString()
    });
    saveDb();
  }
}
ensureDefaultAdmin();

function validAccessCode(code) {
  return /^[A-Za-z0-9_-]{4,32}$/.test(code);
}

function issueSession(res, user, role) {
  const token = crypto.randomBytes(32).toString("hex");
  sessions.set(token, {
    role,
    userId: user.id || null,
    createdAt: Date.now()
  });
  res.json({ token, role, user });
}

function requireRole(role) {
  return (req, res, next) => {
    const header = String(req.headers.authorization || "");
    const match = header.match(/^Bearer\s+(.+)$/i);

    if (!match) return sendError(res, 401, "Please log in first.");

    const token = match[1];
    const session = sessions.get(token);

    if (!session || Date.now() - session.createdAt > SESSION_DURATION) {
      sessions.delete(token);
      return sendError(res, 401, "Your session expired. Please log in again.");
    }

    if (session.role !== role) {
      return sendError(res, 403, "You do not have permission for this page.");
    }

    req.auth = session;
    req.token = token;
    next();
  };
}

function validateCounter(counter, floor, ignoredId = null) {
  return db.tellers.some(teller =>
    teller.id !== ignoredId &&
    teller.floor === floor &&
    String(teller.counter).trim().toLowerCase() === counter.toLowerCase()
  );
}

function duplicateAccessCode(code, ignoredId = null) {
  return db.tellers.some(teller =>
    teller.id !== ignoredId && accessCodeMatches(code, teller)
  );
}

function tellersForFloor(floor) {
  return db.tellers.filter(teller =>
    teller.floor === floor && teller.status === "Active"
  );
}

function ticketDto(ticket) {
  const teller = db.tellers.find(item => item.id === ticket.tellerId);
  return {
    ...ticket,
    tellerName: teller?.name || "Unassigned",
    counter: teller?.counter || "Unassigned"
  };
}

function ownTickets(tellerId) {
  return db.tickets.filter(ticket => ticket.tellerId === tellerId);
}

function createId() {
  return crypto.randomUUID();
}

app.get("/api/health", (req, res) => {
  res.json({ status: "OK", service: "QueueFlow shared queue backend" });
});

// ---------------- Authentication ----------------

app.post("/api/auth/admin/register", (req, res) => {
  const username = String(req.body.username || "").trim();
  const email = normalizeEmail(req.body.email);
  const password = String(req.body.password || "");

  if (!/^[A-Za-z0-9_.-]{3,40}$/.test(username)) {
    return sendError(res, 400, "Username must be 3–40 characters using letters, numbers, dots, underscores or hyphens.");
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) {
    return sendError(res, 400, "Enter a valid email address.");
  }
  if (password.length < 8 || password.length > 128) {
    return sendError(res, 400, "Password must be at least 8 characters.");
  }
  if (db.admins.some(a => a.username.toLowerCase() === username.toLowerCase())) {
    return sendError(res, 409, "That username is already registered.");
  }
  if (db.admins.some(a => normalizeEmail(a.email) === email)) {
    return sendError(res, 409, "That email is already registered.");
  }

  const salt = crypto.randomBytes(16).toString("hex");
  db.admins.push({
    id: createId(), username, email,
    passwordSalt: salt,
    passwordHash: hashAdminPassword(password, salt),
    createdAt: new Date().toISOString()
  });
  saveDb();
  res.status(201).json({ message: "Registration successful. Please sign in." });
});

app.post("/api/auth/admin/forgot-password", (req, res) => {
  const email = normalizeEmail(req.body.email);
  const admin = db.admins.find(a => normalizeEmail(a.email) === email);

  if (admin) {
    const code = String(crypto.randomInt(100000, 1000000));
    const salt = crypto.randomBytes(16).toString("hex");
    passwordResetCodes.set(email, {
      adminId: admin.id,
      salt,
      codeHash: hashAdminPassword(code, salt),
      expiresAt: Date.now() + 10 * 60 * 1000
    });
    console.log("[LOCAL PASSWORD RESET] " + email + ": " + code +
      " (expires in 10 minutes)");
  }

  res.json({
    message: "If the account exists, a reset code has been generated. For local testing, check the server terminal."
  });
});

app.post("/api/auth/admin/reset-password", (req, res) => {
  const email = normalizeEmail(req.body.email);
  const code = String(req.body.code || "").trim();
  const newPassword = String(req.body.newPassword || "");
  const reset = passwordResetCodes.get(email);

  if (newPassword.length < 8 || newPassword.length > 128) {
    return sendError(res, 400, "New password must be at least 8 characters.");
  }
  if (!reset || Date.now() > reset.expiresAt) {
    passwordResetCodes.delete(email);
    return sendError(res, 400, "Reset code is invalid or expired. Request a new code.");
  }

  const actual = Buffer.from(hashAdminPassword(code, reset.salt), "hex");
  const expected = Buffer.from(reset.codeHash, "hex");
  if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) {
    return sendError(res, 400, "Reset code is invalid or expired. Request a new code.");
  }

  const admin = db.admins.find(a => a.id === reset.adminId);
  if (!admin) {
    passwordResetCodes.delete(email);
    return sendError(res, 400, "Admin account not found. Request a new code.");
  }

  const salt = crypto.randomBytes(16).toString("hex");
  admin.passwordSalt = salt;
  admin.passwordHash = hashAdminPassword(newPassword, salt);
  saveDb();
  passwordResetCodes.delete(email);

  res.json({ message: "Password reset successful. Please sign in with your new password." });
});

app.post("/api/auth/admin/login", (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");
  const admin = db.admins.find(a =>
    a.username.toLowerCase() === username.toLowerCase()
  );

  if (!admin || !adminPasswordMatches(password, admin)) {
    return sendError(res, 401, "Invalid admin username or password.");
  }

  issueSession(res, { id: admin.id, username: admin.username, email: admin.email }, "admin");
});

app.post("/api/auth/teller/login", (req, res) => {
  const code = String(req.body.accessCode || "").trim();

  if (!code) return sendError(res, 400, "Enter your teller access code.");

  const teller = db.tellers.find(item =>
    item.status === "Active" && accessCodeMatches(code, item)
  );

  if (!teller) {
    return sendError(res, 401, "Invalid code or inactive teller assignment.");
  }

  issueSession(res, safeTeller(teller), "teller");
});

app.post("/api/auth/logout", (req, res) => {
  const header = String(req.headers.authorization || "");
  const match = header.match(/^Bearer\s+(.+)$/i);
  if (match) sessions.delete(match[1]);
  res.json({ message: "Logged out." });
});

// ---------------- Admin: teller assignments ----------------

app.get("/api/admin/tellers", requireRole("admin"), (req, res) => {
  res.json({ tellers: db.tellers.map(safeTeller) });
});

app.post("/api/admin/tellers", requireRole("admin"), (req, res) => {
  const name = String(req.body.name || "").trim();
  const counter = String(req.body.counter || "").trim();
  const floor = normalizeFloor(req.body.floor);
  const status = req.body.status === "Inactive" ? "Inactive" : "Active";
  const code = String(req.body.accessCode || "").trim();

  if (!name || !counter || !floor) {
    return sendError(res, 400, "Name, counter and valid floor are required.");
  }

  if (!validAccessCode(code)) {
    return sendError(res, 400, "Access code must be 4–32 letters, numbers, underscores or hyphens.");
  }

  if (validateCounter(counter, floor)) {
    return sendError(res, 409, "That counter is already registered on this floor.");
  }

  if (duplicateAccessCode(code)) {
    return sendError(res, 409, "That access code is already assigned to another teller.");
  }

  const salt = crypto.randomBytes(16).toString("hex");
  const teller = {
    id: createId(),
    name,
    counter,
    floor,
    status,
    accessCodeSalt: salt,
    accessCodeHash: hashAccessCode(code, salt),
    createdAt: new Date().toISOString()
  };

  db.tellers.push(teller);
  saveDb();

  res.status(201).json({
    message: "Teller assignment created.",
    teller: safeTeller(teller)
  });
});

app.put("/api/admin/tellers/:id", requireRole("admin"), (req, res) => {
  const teller = db.tellers.find(item => item.id === req.params.id);
  if (!teller) return sendError(res, 404, "Teller assignment not found.");

  const name = String(req.body.name ?? teller.name).trim();
  const counter = String(req.body.counter ?? teller.counter).trim();
  const floor = normalizeFloor(req.body.floor ?? teller.floor);
  const status = req.body.status === "Inactive" ? "Inactive" : "Active";
  const newCode = String(req.body.accessCode || "").trim();

  if (!name || !counter || !floor) {
    return sendError(res, 400, "Name, counter and valid floor are required.");
  }

  if (validateCounter(counter, floor, teller.id)) {
    return sendError(res, 409, "That counter is already registered on this floor.");
  }

  if (newCode) {
    if (!validAccessCode(newCode)) {
      return sendError(res, 400, "Access code must be 4–32 letters, numbers, underscores or hyphens.");
    }
    if (duplicateAccessCode(newCode, teller.id)) {
      return sendError(res, 409, "That access code is already assigned to another teller.");
    }
    const salt = crypto.randomBytes(16).toString("hex");
    teller.accessCodeSalt = salt;
    teller.accessCodeHash = hashAccessCode(newCode, salt);
  }

  Object.assign(teller, { name, counter, floor, status });
  saveDb();

  res.json({ message: "Teller assignment updated.", teller: safeTeller(teller) });
});

app.delete("/api/admin/tellers/:id", requireRole("admin"), (req, res) => {
  const teller = db.tellers.find(item => item.id === req.params.id);
  if (!teller) return sendError(res, 404, "Teller assignment not found.");

  const hasOpenTickets = db.tickets.some(ticket =>
    ticket.tellerId === teller.id &&
    ["Waiting", "Now Serving"].includes(ticket.status)
  );

  if (hasOpenTickets) {
    return sendError(res, 409, "This teller has open tickets. Complete them or deactivate the teller first.");
  }

  db.tellers = db.tellers.filter(item => item.id !== teller.id);
  saveDb();
  res.json({ message: "Teller assignment removed." });
});

// ---------------- Admin: services ----------------

app.get("/api/admin/services", requireRole("admin"), (req, res) => {
  res.json({ services: db.services });
});

app.post("/api/admin/services", requireRole("admin"), (req, res) => {
  const name = String(req.body.name || "").trim();
  const code = String(req.body.code || "").trim().toUpperCase();
  const floor = normalizeFloor(req.body.floor);
  const status = req.body.status === "Inactive" ? "Inactive" : "Active";
  const description = String(req.body.description || "").trim();

  if (!name || !/^[A-Z0-9_-]{1,12}$/.test(code) || !floor) {
    return sendError(res, 400, "Enter a service name, valid service code and floor.");
  }

  if (db.services.some(item => item.code === code)) {
    return sendError(res, 409, "That service code is already in use.");
  }

  const service = {
    id: createId(), name, code, floor, status, description,
    createdAt: new Date().toISOString()
  };

  db.services.push(service);
  saveDb();
  res.status(201).json({ message: "Service created.", service });
});

app.put("/api/admin/services/:id", requireRole("admin"), (req, res) => {
  const service = db.services.find(item => item.id === req.params.id);
  if (!service) return sendError(res, 404, "Service not found.");

  const name = String(req.body.name ?? service.name).trim();
  const code = String(req.body.code ?? service.code).trim().toUpperCase();
  const floor = normalizeFloor(req.body.floor ?? service.floor);
  const status = req.body.status === "Inactive" ? "Inactive" : "Active";
  const description = String(req.body.description ?? service.description).trim();

  if (!name || !/^[A-Z0-9_-]{1,12}$/.test(code) || !floor) {
    return sendError(res, 400, "Enter a service name, valid service code and floor.");
  }

  if (db.services.some(item => item.id !== service.id && item.code === code)) {
    return sendError(res, 409, "That service code is already in use.");
  }

  Object.assign(service, { name, code, floor, status, description });
  saveDb();
  res.json({ message: "Service updated.", service });
});

app.delete("/api/admin/services/:id", requireRole("admin"), (req, res) => {
  const service = db.services.find(item => item.id === req.params.id);
  if (!service) return sendError(res, 404, "Service not found.");

  if (db.tickets.some(ticket => ticket.serviceId === service.id &&
    ["Waiting", "Now Serving"].includes(ticket.status))) {
    return sendError(res, 409, "This service has open tickets. Complete them before deleting.");
  }

  db.services = db.services.filter(item => item.id !== service.id);
  saveDb();
  res.json({ message: "Service deleted." });
});

// ---------------- Kiosk: public ticket issue ----------------

app.get("/api/public/services", (req, res) => {
  const floor = normalizeFloor(req.query.floor);
  const services = db.services.filter(service =>
    service.status === "Active" && (!floor || service.floor === floor)
  );
  res.json({ services });
});

app.post("/api/public/tickets", (req, res) => {
  const name = String(req.body.name || "").trim();
  const floor = normalizeFloor(req.body.floor);
  const serviceId = String(req.body.serviceId || "");

  if (!name || name.length > 100 || !floor || !serviceId) {
    return sendError(res, 400, "Customer name, floor and service are required.");
  }

  const service = db.services.find(item =>
    item.id === serviceId &&
    item.floor === floor &&
    item.status === "Active"
  );

  if (!service) return sendError(res, 400, "The selected service is not active on this floor.");

  const availableTellers = tellersForFloor(floor);
  if (!availableTellers.length) {
    return sendError(res, 409, "No active teller is assigned to this floor yet.");
  }

  // Assign the ticket to the eligible teller with the lightest open workload.
  availableTellers.sort((a, b) => {
    const workload = teller => db.tickets.filter(ticket =>
      ticket.tellerId === teller.id &&
      ["Waiting", "Now Serving"].includes(ticket.status)
    ).length;
    return workload(a) - workload(b) ||
      String(a.lastAssignedAt || "").localeCompare(String(b.lastAssignedAt || ""));
  });

  const teller = availableTellers[0];
  const n = db.nextNumbers[floor]++;
  teller.lastAssignedAt = new Date().toISOString();

  const ticket = {
    id: createId(),
    number: `${floor}-${String(n).padStart(3, "0")}`,
    name,
    floor,
    serviceId: service.id,
    serviceName: service.name,
    serviceCode: service.code,
    tellerId: teller.id,
    status: "Waiting",
    createdAt: new Date().toISOString()
  };

  db.tickets.push(ticket);
  saveDb();

  res.status(201).json({
    message: "Ticket issued successfully.",
    ticket: {
      number: ticket.number,
      name: ticket.name,
      floor: FLOOR_NAMES[floor],
      service: ticket.serviceName,
      status: ticket.status
    }
  });
});

// ---------------- Teller: only their assigned queue ----------------

app.get("/api/teller/me", requireRole("teller"), (req, res) => {
  const teller = db.tellers.find(item => item.id === req.auth.userId);
  if (!teller || teller.status !== "Active") {
    return sendError(res, 403, "This teller assignment is inactive.");
  }
  res.json({ teller: safeTeller(teller) });
});

app.get("/api/teller/queue", requireRole("teller"), (req, res) => {
  const teller = db.tellers.find(item => item.id === req.auth.userId);
  if (!teller || teller.status !== "Active") {
    return sendError(res, 403, "This teller assignment is inactive.");
  }

  const tickets = ownTickets(teller.id);
  res.json({
    teller: safeTeller(teller),
    currentCustomer: tickets.find(ticket => ticket.status === "Now Serving") || null,
    waiting: tickets.filter(ticket => ticket.status === "Waiting"),
    tickets: tickets.slice().reverse().slice(0, 30)
  });
});

app.post("/api/teller/call-next", requireRole("teller"), (req, res) => {
  const teller = db.tellers.find(item => item.id === req.auth.userId);
  if (!teller || teller.status !== "Active") {
    return sendError(res, 403, "This teller assignment is inactive.");
  }

  if (ownTickets(teller.id).some(ticket => ticket.status === "Now Serving")) {
    return sendError(res, 409, "Complete your current customer first.");
  }

  const ticket = db.tickets.find(item =>
    item.tellerId === teller.id && item.status === "Waiting"
  );

  if (!ticket) return sendError(res, 404, "No customers are waiting for your counter.");

  ticket.status = "Now Serving";
  ticket.calledAt = new Date().toISOString();
  saveDb();

  res.json({ message: `Now serving ${ticket.number}.`, currentCustomer: ticketDto(ticket) });
});

app.post("/api/teller/complete", requireRole("teller"), (req, res) => {
  const ticket = ownTickets(req.auth.userId).find(item => item.status === "Now Serving");
  if (!ticket) return sendError(res, 404, "You have no active customer.");

  ticket.status = "Completed";
  ticket.completedAt = new Date().toISOString();
  saveDb();

  res.json({ message: `${ticket.number} completed.`, ticket: ticketDto(ticket) });
});

// ---------------- Public display ----------------

app.get("/api/public/display", (req, res) => {
  const serving = db.tickets.filter(ticket => ticket.status === "Now Serving");
  const waiting = db.tickets.filter(ticket => ticket.status === "Waiting");
  const completed = db.tickets.filter(ticket => ticket.status === "Completed");

  const servingByFloor = { G: [], "2": [], "3": [] };
  for (const ticket of serving) {
    servingByFloor[ticket.floor].push(ticketDto(ticket));
  }

  res.json({
    servingByFloor,
    recentCalls: db.tickets
      .filter(ticket => ticket.status === "Now Serving" || ticket.status === "Completed")
      .slice(-10)
      .reverse()
      .map(ticketDto),
    totals: {
      total: db.tickets.length,
      waiting: waiting.length,
      serving: serving.length,
      completed: completed.length
    }
  });
});

app.get("/api/admin/overview", requireRole("admin"), (req, res) => {
  const totals = {
    total: db.tickets.length,
    waiting: db.tickets.filter(ticket => ticket.status === "Waiting").length,
    serving: db.tickets.filter(ticket => ticket.status === "Now Serving").length,
    completed: db.tickets.filter(ticket => ticket.status === "Completed").length
  };

  const floors = {};
  for (const key of Object.keys(FLOOR_NAMES)) {
    floors[key] = {
      name: FLOOR_NAMES[key],
      tellers: db.tellers.filter(teller => teller.floor === key && teller.status === "Active").length,
      waiting: db.tickets.filter(ticket => ticket.floor === key && ticket.status === "Waiting").length,
      serving: db.tickets.filter(ticket => ticket.floor === key && ticket.status === "Now Serving").map(ticketDto)
    };
  }

  res.json({
    totals,
    floors,
    tellers: db.tellers.map(safeTeller),
    services: db.services,
    recentActivity: db.tickets.slice(-50).reverse().map(ticketDto)
  });
});

// Unknown API paths should return JSON, not an HTML page.
app.use("/api", (req, res) => sendError(res, 404, "API endpoint not found."));
app.use(express.static(ROOT));

app.listen(PORT, HOST, () => {
  console.log(`QueueFlow Auth Server running at http://${HOST}:${PORT}`);
  console.log("Health check: /api/health");
  console.log("Admin demo credentials: admin / QueueFlow@123");
  console.log("For testing only. Set ADMIN_PASSWORD before using on a network.");
});