# Signed challenge protocol v1

This is an alternative to bearer authentication, not a second accepted credential. Configure exactly one mode. Any mixture of bearer and signed settings, incomplete signed settings, malformed/non-Ed25519 public key, or absent settings disables protected endpoints. The public health endpoint remains available. Do not configure production trust without explicit authorization.

## Trust configuration

The backend accepts these server environment variables:

- `REA_AUTH_PUBLIC_KEY_PEM`: one Ed25519 SubjectPublicKeyInfo PEM (`BEGIN PUBLIC KEY`), at most 1024 characters. Never a private key.
- `REA_AUTH_ISSUER`: exact trusted Site origin, printable non-whitespace ASCII, at most 200 characters.
- `REA_AUTH_AUDIENCE`: exact backend origin, same restrictions.
- `REA_API_KEY` must be absent or empty in signed mode.

`kid` is the unpadded base64url SHA-256 digest of the public key's DER SPKI bytes. The signer must derive and verify the same key ID. There is no dynamic key discovery, client-supplied key, algorithm choice, JWT fallback or trust based on `oai-*` headers. Key rotation changes the configured key and restarts this service, invalidating all outstanding challenges. The Site must refuse a challenge from a different key, issuer or audience.

The Site owns the private key. Provision it only under the approved storage/access policy; never transmit it to the backend or expose it in browser code, logs, responses, source control or chat. This backend stores only the public key and short-lived nonce records. Protocol tests generate ephemeral keys in memory only.

## Challenge request

`POST /v1/challenge` is public only when valid signed-mode configuration is active. Send uncompressed `application/json`, at most 1024 bytes, as compact `JSON.stringify` JSON with exactly four fields:

```json
{"method":"POST","path":"/v1/analyze","bodySha256":"lowercase-64-hex-sha256-of-exact-bytes","bodyBytes":1234}
```

The only allowed bindings are POST `/v1/analyze` with 0–4194304 bytes, or GET `/v1/capabilities` with zero bytes and SHA-256 of the empty byte sequence. No other method, path, URL, query, extra field, fractional size or uppercase digest is accepted. Compact JSON is required; whitespace, duplicate fields and noncanonical number representations are rejected.

The response has these exact fields (JSON member order is not the signature protocol):

```text
protocol: "REA-ED25519-V1"
kid: base64url(SHA256(SPKI DER)), 43 characters
nonce: 32 random bytes encoded as unpadded base64url, 43 characters
issuer: configured exact issuer
audience: configured exact audience
iat: integer Unix seconds from backend clock
exp: iat + 60 seconds
method: requested allowed method
path: requested allowed path
bodySha256: requested lowercase hex digest
bodyBytes: requested integer byte length
```

The Site must verify protocol, kid, issuer, audience, lifetime (at most 60 seconds), method, path, exact body hash and exact byte length before signing. Nonce/header values must never be accepted from a public browser endpoint as an arbitrary signing oracle. Only the Site's authenticated owner-authorized tool route may request and sign a challenge for its own fixed backend operation.

## Exact signed bytes

Join the following fields with a single LF (`\n`), UTF-8 encode, and do not append a trailing newline. Integers use ordinary base-10 decimal representation without leading zeroes:

```text
REA-ED25519-V1
kid
issuer
audience
nonce
iat
exp
method
path
bodySha256
bodyBytes
```

Sign those exact bytes with Ed25519 (no pre-hash signature variant). The signature is 64 bytes, encoded as unpadded base64url (86 characters). Send the protected request with:

```text
Authorization: REA-Ed25519 base64url(UTF8(JSON.stringify({kid,nonce,signature})))
```

The full header value must be at most 512 ASCII characters. The envelope must be compact JSON with exactly `kid`, `nonce`, `signature`; duplicate fields, noncanonical base64url, padding, extra fields and duplicate Authorization headers are rejected. Authorization fields are credentials for one operation and should not be logged.

The backend retrieves the issued record from memory, then verifies its fixed algorithm/key ID, issuer/audience, issue and expiration time, exact request method/path and signature. It reads and hashes the bounded upload, checks actual byte count/digest, and synchronously checks-and-deletes the nonce before ELF validation or parser dispatch. A signature cannot authorize changed bytes. GET capabilities uses the exact empty body and consumes the nonce too.

A nonce may authorize one dispatch only. Concurrent replay after consumption, retries after an analysis error, unknown/expired records and process restarts fail closed. A hash/length mismatch does not consume a valid nonce; the correct signed bytes may still be retried before expiry. A busy response before consumption may also be retried within expiry. Clients should normally obtain a new challenge for a deliberate retry.

## Resource and lifecycle contract

- At most 64 outstanding nonce records; 60-second lifetime, pruned on requests.
- A global token bucket permits a burst of 16 challenge attempts and replenishes one token every two seconds. Admission is charged before parsing, including malformed requests.
- At most four concurrent challenge-body readers, each at most 1024 bytes and two seconds. Overall server connection/header/time limits still apply.
- No persistent nonce store, timer-based sweeper, external cache or database. Restart and shutdown clear pending authorization.
- Run one Node process and one service replica. Do not use Node cluster, autoscaling or multiple replicas with this in-memory design. Multi-replica routing would reject challenges sent to another process; use a reviewed shared atomic nonce store before scaling.
- Public challenge exhaustion can temporarily deny service. These bounds constrain resource usage; they do not claim public DoS immunity. Per-IP forwarding headers are deliberately not trusted.
- An authenticated upload still occupies the existing single analysis slot and all existing upload/output/parser limits apply.

## Deployment status and validation

The previous fail-closed image was built and started on the free Render service. Signed-mode activation requires the reviewed code deployment, approved Site key provisioning and backend public-key/issuer/audience configuration. No secret or production key is included in this package. After activation, test valid authorization, wrong signatures, body mutation, replay, expiry and a real ELF fixture before claiming the Site's native tools are working.
