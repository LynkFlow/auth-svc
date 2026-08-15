import fs from "node:fs";
import path from "node:path";
import { generateKeyPairSync } from "node:crypto";

const secretsDirectory = path.resolve(process.cwd(), ".secrets");
const privateKeyPath = path.join(secretsDirectory, "jwt-private.pem");
const publicKeyPath = path.join(secretsDirectory, "jwt-public.pem");
const force = process.argv.includes("--force");

if (!force && (fs.existsSync(privateKeyPath) || fs.existsSync(publicKeyPath))) {
  throw new Error(
    "JWT keys already exist. Refusing to overwrite them without --force.",
  );
}

const { privateKey, publicKey } = generateKeyPairSync("rsa", {
  modulusLength: 3_072,
  publicKeyEncoding: {
    type: "spki",
    format: "pem",
  },
  privateKeyEncoding: {
    type: "pkcs8",
    format: "pem",
  },
});

fs.mkdirSync(secretsDirectory, { recursive: true });
fs.writeFileSync(privateKeyPath, privateKey, {
  encoding: "utf8",
  mode: 0o600,
});
fs.writeFileSync(publicKeyPath, publicKey, {
  encoding: "utf8",
  mode: 0o644,
});

console.log("Generated JWT signing keys.", {
  privateKeyPath,
  publicKeyPath,
});
