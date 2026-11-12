const express = require("express");
const path = require("path");
const app = express();
const vulnerable = process.env.LAB_MODE === "vulnerable";
app.set("env", vulnerable ? "development" : "production");

app.get("/api/v1/health", (_req, res) => {
  res.json({status: "ok", mode: vulnerable ? "vulnerable" : "secure"});
});

if (vulnerable) {
  app.get(["/debug", "/__express"], (_req, _res, next) => {
    next(new TypeError("Lab-only Express debug error"));
  });
  app.get("/package.json", (_req, res) => res.sendFile(path.join(__dirname, "package.json")));
  app.get("/.env", (_req, res) => res.type("text/plain").send("DB_PASSWORD=lab-only-express-password\nJWT_SECRET=lab-only-jwt-secret\n"));
  app.get("/main.js.map", (_req, res) => res.sendFile(path.join(__dirname, "main.js.map")));
}

app.use((err, _req, res, _next) => {
  res.status(500);
  if (vulnerable) {
    res.set("Content-Type", "text/html").send(`<pre>TypeError: ${err.message}\n${err.stack}</pre>`);
  } else {
    res.json({error: "Internal Server Error"});
  }
});

app.listen(3000, "0.0.0.0");
