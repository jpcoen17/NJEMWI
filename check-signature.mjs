import crypto from "node:crypto";

const body = '{"ok":true,"protocolVersion":"v1"}';
const secret = process.env.AGENT_GAMES_HMAC_SECRET;

if (!secret) {
  console.log("SECRET KOSONG");
  process.exit(1);
}

const signature = crypto
  .createHmac("sha256", secret)
  .update(body)
  .digest("hex");

console.log(signature);
