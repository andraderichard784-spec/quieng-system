
"use strict";

const express = require("express");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

// CREATE THE EXPRESS APP BEFORE USING app.use()
const app = express();

const PORT = Number(process.env.PORT || process.env.AUTH_PORT || 3000);
const HOST = "0.0.0.0";
const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, "data");
const DB_FILE = path.join(DATA_DIR, "queueflow-auth-db.json");

const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "12345";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "12345";
const passwordResetCodes = new Map();

const sessions = new Map();
const SESSION_DURATION = 12 * 60 * 60 * 1000;

const ALLOWED_ORIGINS = [
  "http://127.0.0.1:5500",
  "http://localhost:5500"
];

// CORS CONFIGURATION
app.use((req, res, next) => {
  const origin = req.headers.origin;

  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
  }

  res.setHeader(
    "Access-Control-Allow-Methods",
    "GET, POST, PUT, DELETE, OPTIONS"
  );

  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization"
  );

  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  next();
});

const FLOOR_NAMES = {
  G: "Ground Floor",
  "2": "2nd Floor",
  "3": "3rd Floor"
};

app.disable("x-powered-by");
app.use(express.json({ limit: "100kb" }));

