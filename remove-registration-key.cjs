const fs = require("fs");

const serverPath = "server-auth.js";
const htmlPath = "admin.html";

let server = fs.readFileSync(serverPath, "utf8");
let html = fs.readFileSync(htmlPath, "utf8");

// Remove registration-key configuration.
server = server.replace(
  /^const ADMIN_REGISTRATION_KEY = .*;\r?\n/m,
  ""
);

// Remove the backend requirement to configure a registration key.
server = server.replace(
  /[ \t]*if\s*\(!ADMIN_REGISTRATION_KEY\)\s*\{\s*return sendError\(res,\s*503,\s*"Registration is disabled\.[\s\S]*?\);\s*\}\s*\r?\n/,
  ""
);

// Remove registration-key validation.
server = server.replace(
  /^[ \t]*const suppliedKey = String\(req\.body\.registrationKey \|\| ""\);\s*\r?\n/m,
  ""
);

server = server.replace(
  /^[ \t]*if \(suppliedKey !== ADMIN_REGISTRATION_KEY\) \{\s*\r?\n[ \t]*return sendError\(res,\s*403,\s*"Invalid registration key\."\);\s*\r?\n[ \t]*\}\s*\r?\n/m,
  ""
);

// Remove the Registration Key field from the form.
html = html.replace(
  /^[ \t]*<label for="regKey">Registration Key<\/label>\s*\r?\n[ \t]*<input id="regKey" name="registrationKey"[^>]*>\s*\r?\n/m,
  ""
);

// Stop sending registrationKey from the frontend.
html = html.replace(
  /^[ \t]*registrationKey: \$\("regKey"\)\.value,?\s*\r?\n/m,
  ""
);

if (/ADMIN_REGISTRATION_KEY|suppliedKey/.test(server)) {
  throw new Error("Server key references remain. No files were changed.");
}
if (/regKey|registrationKey|Registration Key/.test(html)) {
  throw new Error("Frontend key references remain. No files were changed.");
}
if (!server.includes('app.post("/api/auth/admin/register"')) {
  throw new Error("Admin registration endpoint not found. No files were changed.");
}

// Create timestamped backups before saving.
const stamp = new Date().toISOString().replace(/[:.]/g, "-");
fs.copyFileSync(serverPath, `${serverPath}.${stamp}.bak`);
fs.copyFileSync(htmlPath, `${htmlPath}.${stamp}.bak`);

fs.writeFileSync(serverPath, server);
fs.writeFileSync(htmlPath, html);

console.log("SUCCESS: Registration Key removed from server and frontend.");
console.log("Backups created with timestamp:", stamp);
