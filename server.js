import http from "node:http";
import { readFile } from "node:fs/promises";
import { checkToolCall, policy } from "./firewall.js";

const PORT = process.env.PORT || 3000;
const log = [];

function send(res, status, body, type = "application/json") {
  res.writeHead(status, { "Content-Type": type });
  res.end(type === "application/json" ? JSON.stringify(body) : body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (c) => (data += c));
    req.on("end", () => {
      try { resolve(data ? JSON.parse(data) : {}); } catch (e) { reject(e); }
    });
  });
}

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === "GET" && req.url === "/") {
      const html = await readFile(new URL("./index.html", import.meta.url), "utf8");
      return send(res, 200, html, "text/html; charset=utf-8");
    }
    if (req.method === "GET" && req.url === "/api/policy") return send(res, 200, { policy });
    if (req.method === "GET" && req.url === "/api/log") return send(res, 200, { log });

    if (req.method === "POST" && req.url === "/api/check") {
      const { name, call } = await readBody(req);
      if (!call || !call.tool_name) return send(res, 400, { error: "Missing call.tool_name" });
      const decision = await checkToolCall(call);
      const entry = { id: log.length + 1, time: new Date().toISOString(), name: name || "Custom call", call, decision, human: null };
      log.push(entry);
      return send(res, 200, entry);
    }

    if (req.method === "POST" && req.url === "/api/review") {
      const { id, verdict } = await readBody(req);
      const entry = log.find((e) => e.id === id);
      if (!entry) return send(res, 404, { error: "Not found" });
      entry.human = { verdict, time: new Date().toISOString() };
      return send(res, 200, entry);
    }

    send(res, 404, { error: "Not found" });
  } catch (err) {
    console.error(err);
    send(res, 500, { error: err.message });
  }
});

server.listen(PORT, () => console.log(`Agent Firewall demo running at http://localhost:${PORT}`));
