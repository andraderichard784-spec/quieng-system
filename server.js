
const express = require("express");
const path = require("path");

const app = express();
const PORT = 3000;

app.use(express.json());
app.use(express.static(__dirname));

// Shared queue data managed by the server
let customers = [];
let nextNumber = 1;
let currentCustomer = null;

app.get("/api/status", (req, res) => {
  res.json({
    status: "OK",
    message: "Queue Management System server is running!"
  });
});

// Get all queue data
app.get("/api/queue", (req, res) => {
  res.json({
    customers,
    currentCustomer,
    nextNumber
  });
});

// Register a customer
app.post("/api/queue", (req, res) => {
  const name = String(req.body.name || "").trim();
  const service = String(req.body.service || "").trim();

  if (!name || !service) {
    return res.status(400).json({
      error: "Customer name and service are required."
    });
  }

  const number = `Q-${String(nextNumber++).padStart(3, "0")}`;

  const customer = {
    id: Date.now().toString() + "-" + number,
    number,
    name,
    service,
    status: "Waiting",
    createdAt: new Date().toISOString()
  };

  customers.push(customer);

  res.status(201).json({
    message: "Customer registered successfully.",
    customer
  });
});

// Call the next waiting customer
app.post("/api/queue/next", (req, res) => {
  if (currentCustomer) {
    return res.status(409).json({
      error: "Complete the current customer first."
    });
  }

  currentCustomer = customers.find(
    customer => customer.status === "Waiting"
  ) || null;

  if (!currentCustomer) {
    return res.status(404).json({
      error: "No customers are waiting."
    });
  }

  currentCustomer.status = "Serving";

  res.json({
    message: `Now serving ${currentCustomer.number}.`,
    currentCustomer
  });
});

// Complete the current customer
app.post("/api/queue/complete", (req, res) => {
  if (!currentCustomer) {
    return res.status(404).json({
      error: "There is no active customer to complete."
    });
  }

  const completedCustomer = currentCustomer;
  completedCustomer.status = "Completed";
  completedCustomer.completedAt = new Date().toISOString();

  currentCustomer = null;

  res.json({
    message: `${completedCustomer.number} completed.`,
    customer: completedCustomer
  });
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});