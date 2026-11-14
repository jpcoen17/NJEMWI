import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const PORT = process.env.PORT || 8899;
const SECRET = process.env.AGENT_GAMES_HMAC_SECRET || "";

const CURRENT_FILE = fileURLToPath(import.meta.url);

const STORE_FILE = path.join(
  path.dirname(CURRENT_FILE),
  "proof-used.json"
);

// Riwayat proof yang pernah APPROVE.
// Seed ini berasal dari Practice sebelumnya yang sudah berhasil APPROVE.
const usedProofs = new Map([
  [
    "0x470768ff76bf42a7855154b1a6ec7a0a",
    "practice_470768ff-76bf-42a7-8551-54b1a6ec7a0a"
  ]
]);

// Load riwayat dari file lokal
try {
  const saved = JSON.parse(fs.readFileSync(STORE_FILE, "utf8"));

  for (const [proof, taskId] of Object.entries(saved)) {
    usedProofs.set(proof.toLowerCase(), taskId);
  }
} catch (err) {
  if (err.code !== "ENOENT") {
    throw new Error("Proof history rusak/tidak bisa dibaca. Hentikan server: " + err.message);
  }
}

function saveUsedProofs() {
  const data = Object.fromEntries(usedProofs);
  const tempFile = STORE_FILE + ".tmp";

  fs.writeFileSync(tempFile, JSON.stringify(data, null, 2));
  fs.renameSync(tempFile, STORE_FILE);
}

function hmacRaw(body, secret) {
  return crypto.createHmac("sha256", secret).update(body).digest("hex");
}

function validSignature(rawBody, header) {
  if (!SECRET || !header) return false;

  const expected = hmacRaw(rawBody, SECRET);
  const a = Buffer.from(expected);
  const b = Buffer.from(String(header).replace(/^sha256=/, "").trim());

  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function signResponse(obj) {
  const body = JSON.stringify(obj);
  return { body, sig: hmacRaw(body, SECRET) };
}

// ---- Proof Gatekeeper ----
function decideGatekeeper(input, taskId) {
  // 1. Anti replay: cek proof_tx sebelum pemeriksaan lainnya
  const proofTx = String(input.proof_tx || "").toLowerCase();

  if (proofTx && usedProofs.has(proofTx)) {
    const previousTask = usedProofs.get(proofTx);

    // Retry task yang sama tetap boleh diproses secara idempotent
    if (previousTask !== taskId) {
      return "PROOF_REUSED";
    }
  }

  // 2. VK harus cocok
  if (input.proof_vk !== input.registered_vk) {
    return "VK_SUBSTITUTION";
  }

  // 3. Saldo minimum
  try {
    const balance = BigInt(input.public_balance ?? "0");
    const minimum = BigInt(input.minimum ?? "0");

    if (balance < minimum) return "INSUFFICIENT_BALANCE";
  } catch {
    return "INVALID_BALANCE";
  }

  // 4. Expiry
  if (input.expiry_block != null && input.current_block != null) {
    if (Number(input.current_block) >= Number(input.expiry_block)) {
      return "EXPIRED";
    }
  }

  // 5. Recipient
  const rec = String(input.recipient || "").toLowerCase();
  const cond = String(input.condition_recipient || "").toLowerCase();

  if (cond && rec && rec !== cond) {
    return "RECIPIENT_MISMATCH";
  }

  // 6. Amount cap
  if (input.max_transfer != null && input.amount != null) {
    try {
      if (BigInt(input.amount) > BigInt(input.max_transfer)) {
        return "AMOUNT_EXCEEDS_CAP";
      }
    } catch {
      return "INVALID_AMOUNT";
    }
  }

  return null;
}

// ---- HTTP server ----
const server = http.createServer((req, res) => {
  const chunks = [];
  let totalSize = 0;

  req.on("data", (chunk) => {
    totalSize += chunk.length;

    if (totalSize > 1_000_000) {
      res.writeHead(413).end();
      req.destroy();
      return;
    }

    chunks.push(chunk);
  });

  req.on("end", () => {
    const raw = Buffer.concat(chunks);

    if (req.method === "GET" && req.url === "/health") {
      res.writeHead(200, { "content-type": "application/json" });
      return res.end(JSON.stringify({
        ok: true,
        agent: "JemBOT",
        uptime: process.uptime()
      }));
    }

    if (req.method !== "POST" || !req.url.startsWith("/agent")) {
      res.writeHead(404).end();
      return;
    }

    let parsed;

    try {
      parsed = JSON.parse(raw.toString("utf8"));
    } catch {
      const r = signResponse({ ok: false, error: "invalid_json" });
      res.writeHead(400, {
        "content-type": "application/json",
        "x-agent-games-signature": r.sig
      });
      return res.end(r.body);
    }

    // Preflight
    if (parsed.type === "agent-games.preflight" ||
        (parsed.type && !parsed.input)) {
      const r = signResponse({ ok: true, protocolVersion: "v1" });

      res.writeHead(200, {
        "content-type": "application/json",
        "x-agent-games-signature": r.sig
      });

      return res.end(r.body);
    }

    // HMAC verification
    const sig = req.headers["x-agent-games-signature"];

    if (!validSignature(raw, sig)) {
      const r = signResponse({
        ok: false,
        error: "invalid_signature"
      });

      res.writeHead(401, {
        "content-type": "application/json",
        "x-agent-games-signature": r.sig
      });

      return res.end(r.body);
    }

    if (parsed.type === "agent-games.proof-gatekeeper.v1") {
      const input = parsed.input || {};
      const taskId = parsed.task_id || "";

      const reason = decideGatekeeper(input, taskId);
      const decision = reason ? "REJECT" : "APPROVE";

      const payload = {
        decision,
        reason_code: reason || "ALL_CHECKS_PASSED"
      };

      if (input.proof_tx) {
        payload.proof_tx = input.proof_tx;
      }

      // Simpan hanya transaksi yang berhasil APPROVE
      // Jika penyimpanan gagal, jangan keluarkan APPROVE.
      if (!reason && input.proof_tx) {
        try {
          usedProofs.set(
            String(input.proof_tx).toLowerCase(),
            taskId
          );

          saveUsedProofs();
        } catch (err) {
          usedProofs.delete(String(input.proof_tx).toLowerCase());

          payload.decision = "REJECT";
          payload.reason_code = "REPLAY_STORE_ERROR";

          console.error("[gk] Failed to save proof history:", err.message);
        }
      }

      const r = signResponse(payload);

      console.log(
        `[gk] ${taskId} -> ${payload.decision} ${payload.reason_code}`
      );

      res.writeHead(200, {
        "content-type": "application/json",
        "x-agent-games-signature": r.sig
      });

      return res.end(r.body);
    }

    const r = signResponse({
      ok: false,
      error: "unknown_task_type",
      type: parsed.type || null
    });

    res.writeHead(400, {
      "content-type": "application/json",
      "x-agent-games-signature": r.sig
    });

    return res.end(r.body);
  });
});

server.listen(PORT, () => {
  console.log(`JemBOT agent listening on :${PORT}`);
  console.log(`Loaded ${usedProofs.size} used proof(s)`);
});
