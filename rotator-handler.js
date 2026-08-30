"use strict";

// ESC External Rotator Adapter — demonstrates sub claim verification
//
// Pulumi Cloud POSTs to this endpoint with a JWT in the Authorization header.
// The JWT sub claim identifies the exact ESC environment that triggered the
// rotation: "pulumi:environments:org:<org>:env:<env>"
//
// This adapter uses only Node.js 18+ built-ins (no npm dependencies needed).

const crypto = require("crypto");

const JWKS_URI = "https://api.pulumi.com/oidc/.well-known/jwks";
const PULUMI_ISSUER = "https://api.pulumi.com";

// Simple in-memory JWKS cache to avoid fetching on every invocation
let jwksCache = null;
let jwksCacheTime = 0;
const CACHE_TTL_MS = 10 * 60 * 1000;

async function getJwks() {
  if (jwksCache && Date.now() - jwksCacheTime < CACHE_TTL_MS) {
    return jwksCache;
  }
  const res = await fetch(JWKS_URI);
  if (!res.ok) throw new Error(`Failed to fetch JWKS: ${res.status}`);
  jwksCache = await res.json();
  jwksCacheTime = Date.now();
  return jwksCache;
}

function base64urlDecode(str) {
  const padded = str + "=".repeat((4 - (str.length % 4)) % 4);
  return Buffer.from(padded.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

// Verify the JWT and return the decoded payload.
// Validates: RS256 signature, issuer, audience, expiry.
async function verifyJwt(token, expectedAudience) {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("Invalid JWT format");

  const [headerB64, payloadB64, signatureB64] = parts;
  const header = JSON.parse(base64urlDecode(headerB64).toString("utf8"));
  const payload = JSON.parse(base64urlDecode(payloadB64).toString("utf8"));

  const now = Math.floor(Date.now() / 1000);
  if (payload.exp && payload.exp < now) throw new Error("Token expired");
  if (payload.iss !== PULUMI_ISSUER) throw new Error(`Invalid issuer: ${payload.iss}`);
  if (payload.aud !== expectedAudience) throw new Error(`Invalid audience: ${payload.aud}`);

  const jwks = await getJwks();
  const jwk = jwks.keys.find((k) => k.kid === header.kid);
  if (!jwk) throw new Error(`No JWKS key found for kid: ${header.kid}`);

  const cryptoKey = await crypto.webcrypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );

  const valid = await crypto.webcrypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    cryptoKey,
    base64urlDecode(signatureB64),
    Buffer.from(`${headerB64}.${payloadB64}`)
  );
  if (!valid) throw new Error("JWT signature verification failed");

  return payload;
}

// Verify the body_hash claim: sha256-<base64(SHA-256(rawBody))>
function verifyBodyHash(rawBody, bodyHashClaim) {
  if (!bodyHashClaim) return; // claim absent — skip
  const digest = crypto.createHash("sha256").update(rawBody).digest("base64");
  const computed = `sha256-${digest}`;
  if (computed !== bodyHashClaim) {
    throw new Error("body_hash mismatch — request body may have been tampered");
  }
}

// Verify the sub claim identifies an allowed ESC environment.
//
// Sub format: "pulumi:environments:org:<org>:env:<env>"
//
// ALLOWED_ORG (required): only accept requests from this org.
// ALLOWED_ENV (optional): if set, restrict to this specific environment;
//   if omitted, any environment in the org is accepted.
function verifySubClaim(sub) {
  const allowedOrg = process.env.ALLOWED_ORG;
  const allowedEnv = process.env.ALLOWED_ENV;

  if (!allowedOrg) throw new Error("ALLOWED_ORG env var is not configured");

  if (allowedEnv) {
    // Exact match: only this specific environment may call us
    const expected = `pulumi:environments:org:${allowedOrg}:env:${allowedEnv}`;
    if (sub !== expected) {
      throw Object.assign(
        new Error(`Unauthorized sub: expected "${expected}", got "${sub}"`),
        { statusCode: 403 }
      );
    }
  } else {
    // Prefix match: any environment in the org is allowed
    const prefix = `pulumi:environments:org:${allowedOrg}:env:`;
    if (!sub.startsWith(prefix)) {
      throw Object.assign(
        new Error(`Unauthorized sub: "${sub}" is not in org "${allowedOrg}"`),
        { statusCode: 403 }
      );
    }
  }
}

exports.handler = async (event) => {
  // API Gateway v2 may base64-encode the body
  const rawBody = event.isBase64Encoded
    ? Buffer.from(event.body || "", "base64").toString("utf-8")
    : event.body || "";

  try {
    // 1. Extract the bearer token
    const authHeader = event.headers?.authorization || "";
    if (!authHeader.startsWith("Bearer ")) {
      return respond(401, { error: "Missing or malformed Authorization header" });
    }
    const token = authHeader.slice(7);

    // 2. Verify JWT signature + standard claims (iss, aud, exp)
    const adapterUrl = process.env.ADAPTER_URL;
    if (!adapterUrl) throw new Error("ADAPTER_URL env var is not configured");

    const payload = await verifyJwt(token, adapterUrl);

    // 3. Verify the sub claim — this is the key authorization check.
    //    Without it, any Pulumi environment in any org could call your adapter.
    verifySubClaim(payload.sub || "");

    // 4. Verify body integrity
    verifyBodyHash(rawBody, payload.body_hash);

    // 5. Parse the rotation request
    const body = JSON.parse(rawBody);
    const { state } = body;

    // 6. Perform rotation — generate a new secret.
    //    The previous key is preserved in `previousApiKey` so applications can
    //    finish using it before the rotation schedule runs again.
    const newApiKey = crypto.randomBytes(32).toString("hex");
    const rotatedAt = new Date().toISOString();

    const newState = {
      apiKey: newApiKey,
      previousApiKey: state?.apiKey ?? null,
      rotatedAt,
    };

    console.log(`Rotated credentials at ${rotatedAt} (sub=${payload.sub})`);
    return respond(200, newState);
  } catch (err) {
    const status = err.statusCode ?? (isAuthError(err) ? 401 : 500);
    console.error(`[${status}] ${err.message}`);
    return respond(status, { error: err.message });
  }
};

function isAuthError(err) {
  return ["expired", "issuer", "audience", "signature", "JWT"].some((k) =>
    err.message.includes(k)
  );
}

function respond(statusCode, body) {
  return {
    statusCode,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  };
}
