"use strict";
const fs = require("fs");

const serverPath = "server-auth.js";
const htmlPath = "admin.html";
let server = fs.readFileSync(serverPath, "utf8");
let html = fs.readFileSync(htmlPath, "utf8");

if (server.includes("/api/auth/admin/register")) {
  console.log("Admin auth endpoints already exist. No server changes made.");
  process.exit(0);
}

if (!html.includes('id="registerForm"') ||
    !html.includes('id="regPassword"') ||
    !html.includes('id="resetForm"')) {
  throw new Error("Expected auth forms were not found. No files changed.");
}

for (const file of [serverPath, htmlPath]) {
  const backup = file + ".pre-admin-auth.bak";
  if (!fs.existsSync(backup)) fs.copyFileSync(file, backup);
}

function replaceOnce(source, oldText, newText, label) {
  const first = source.indexOf(oldText);
  if (first < 0 || source.indexOf(oldText, first + oldText.length) >= 0) {
    throw new Error("Could not uniquely locate " + label + ". No patched files written.");
  }
  return source.slice(0, first) + newText + source.slice(first + oldText.length);
}

server = replaceOnce(
  server,
  'const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "QueueFlow@123";',
  'const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "QueueFlow@123";\n' +
  'const ADMIN_REGISTRATION_KEY = process.env.ADMIN_REGISTRATION_KEY || "";\n' +
  'const passwordResetCodes = new Map();',
  "admin configuration"
);

server = replaceOnce(
  server,
  "    tellers: [],\n    services: [],",
  "    admins: [],\n    tellers: [],\n    services: [],",
  "empty database schema"
);

server = replaceOnce(
  server,
  "  if (!Array.isArray(db.tickets)) db.tickets = [];",
  "  if (!Array.isArray(db.tickets)) db.tickets = [];\n" +
  "  if (!Array.isArray(db.admins)) db.admins = [];",
  "database normalization"
);

const helpers = `
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

`;

server = replaceOnce(
  server,
  "function validAccessCode(code) {",
  helpers + "function validAccessCode(code) {",
  "admin password helpers"
);

const loginStart = server.indexOf('app.post("/api/auth/admin/login"');
const tellerStart = server.indexOf('app.post("/api/auth/teller/login"', loginStart);
if (loginStart < 0 || tellerStart < 0) {
  throw new Error("Could not locate login routes. No patched files written.");
}

const routes = `app.post("/api/auth/admin/register", (req, res) => {
  if (!ADMIN_REGISTRATION_KEY) {
    return sendError(res, 503, "Registration is disabled. Configure ADMIN_REGISTRATION_KEY and restart the server.");
  }

  const suppliedKey = String(req.body.registrationKey || "");
  const username = String(req.body.username || "").trim();
  const email = normalizeEmail(req.body.email);
  const password = String(req.body.password || "");

  if (suppliedKey !== ADMIN_REGISTRATION_KEY) {
    return sendError(res, 403, "Invalid registration key.");
  }
  if (!/^[A-Za-z0-9_.-]{3,40}$/.test(username)) {
    return sendError(res, 400, "Username must be 3–40 characters using letters, numbers, dots, underscores or hyphens.");
  }
  if (!/^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(email) || email.length > 254) {
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

`;

server = server.slice(0, loginStart) + routes + server.slice(tellerStart);

const regStart = html.indexOf('<form id="registerForm"');
const regEnd = html.indexOf("</form>", regStart);
if (regStart < 0 || regEnd < 0) {
  throw new Error("Could not locate the registration form. No patched files written.");
}
if (!html.includes('id="regKey"')) {
  html = html.slice(0, regEnd) +
    '    <label for="regKey">Registration Key</label>\n' +
    '    <input id="regKey" name="registrationKey" type="password" required autocomplete="off" placeholder="Enter registration key">\n' +
    html.slice(regEnd);
}

html = replaceOnce(
  html,
  'password: $("regPassword").value\n      })',
  'password: $("regPassword").value,\n        registrationKey: $("regKey").value\n      })',
  "registration request payload"
);

fs.writeFileSync(serverPath, server, "utf8");
fs.writeFileSync(htmlPath, html, "utf8");

console.log("SUCCESS: Admin Register, Forgot Password and Reset Password endpoints added.");
console.log("Backups: server-auth.js.pre-admin-auth.bak and admin.html.pre-admin-auth.bak");
console.log("Default admin email for password recovery: admin@queueflow.local");
