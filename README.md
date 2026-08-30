# ESC External Rotator — Sub Claim Verification

This example shows how to implement a [Pulumi ESC external rotator](https://www.pulumi.com/docs/esc/providers/rotators/external/) adapter that verifies the JWT `sub` claim to restrict which ESC environments are allowed to trigger rotation.

## Why verify the sub claim?

When Pulumi Cloud calls your adapter it includes a signed JWT. Verifying the signature (via JWKS) proves the request came from Pulumi, but it does not prove which environment sent it. Without `sub` verification, **any ESC environment in any Pulumi org** that knows your adapter URL could trigger a rotation.

The `sub` claim carries the full identity of the calling environment:

```
pulumi:environments:org:<org>:env:<env>
```

Checking it lets you enforce that only a specific environment — or any environment within a trusted org — can rotate your credentials.

## What this example does

- Deploys an AWS Lambda + API Gateway HTTP API as the rotator adapter
- Creates a Pulumi ESC environment configured to use that adapter via `fn::rotate::external`
- The adapter performs four checks on every request:
  1. **JWT signature** — verifies RS256 signature using Pulumi's JWKS endpoint
  2. **Standard claims** — validates `iss`, `aud`, and `exp`
  3. **`sub` claim** — rejects requests from any org/environment not explicitly allowed
  4. **Body hash** — verifies the `body_hash` claim to detect tampering

The adapter uses only Node.js 18+ built-ins (`crypto`, `fetch`) — no npm dependencies to bundle.

## Project structure

```
.
├── rotator-handler.js   # Lambda handler — JWT validation and rotation logic
├── index.ts             # Pulumi program — deploys Lambda, API GW, and ESC environment
├── Pulumi.yaml
└── Pulumi.dev.yaml      # Stack config — set your org, env, and AWS region here
```

## Prerequisites

- [Pulumi CLI](https://www.pulumi.com/docs/install/) and an account on Pulumi Cloud
- AWS credentials configured
- Node.js 18+

## Deploy

```bash
npm install
pulumi stack init dev
pulumi up
```

On first deploy, fill in `Pulumi.dev.yaml` (or `pulumi config set`) with your values:

| Config key   | Description                                                                  |
|--------------|------------------------------------------------------------------------------|
| `allowedOrg` | Pulumi org name. Only JWTs with a matching `sub` org segment are accepted.   |
| `allowedEnv` | ESC environment name. Also used as the name of the created ESC environment.  |
| `escProject` | ESC project to create the environment in. Defaults to `default`.             |
| `aws:region` | AWS region to deploy the Lambda and API Gateway into.                        |

After `pulumi up`, the stack exports:

- `rotatorUrl` — the adapter endpoint (matches the `url` in the ESC YAML)
- `environmentName` — the name of the created ESC environment

## How sub verification works

In `rotator-handler.js`, `verifySubClaim` is called after the JWT signature is confirmed:

```javascript
// ALLOWED_ORG is required — reject anything not from this org
// ALLOWED_ENV is optional — omit to allow any environment within the org

if (allowedEnv) {
  // Exact match: only this specific environment may trigger rotation
  const expected = `pulumi:environments:org:${allowedOrg}:env:${allowedEnv}`;
  if (sub !== expected) { /* reject 403 */ }
} else {
  // Prefix match: any environment in the org is allowed
  const prefix = `pulumi:environments:org:${allowedOrg}:env:`;
  if (!sub.startsWith(prefix)) { /* reject 403 */ }
}
```

## Rotation behavior

On each rotation call the adapter generates a new random API key and returns:

```json
{
  "apiKey": "<new-key>",
  "previousApiKey": "<previous-key-or-null>",
  "rotatedAt": "2025-01-16T10:00:00Z"
}
```

The previous key is preserved in state so applications have time to pick up the new key before the old one is revoked. Configure your rotation schedule to be less frequent than your application's ESC config refresh interval.

## ESC environment YAML

The created ESC environment contains:

```yaml
values:
  myCredentials:
    fn::rotate::external:
      inputs:
        url: <rotatorUrl>
        request:
          service: my-service
```

Access the rotated credentials in other environments by importing this one, then referencing `myCredentials.apiKey`.
