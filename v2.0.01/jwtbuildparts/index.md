---
title: JWTBuildParts
kind: typedef
longname: JWTBuildParts
group: JWT/Types
---

# JWTBuildParts

<SourceLink href="/source/jwt-js/#L36" label="jwt.js:36" />

**Properties**

- `header` (Object) — The final header used for the token
- `b64_header` (string) — The header encoded in base 64
- `payload` (Object) — The final payload used for the JWT
- `b64_payload` (string) — The final payload encoded in base 64
- `signature` (string) — The signature of the token
- `token_wo_signature` (string) — The JWT token without the signature ("jose.payload" format)
- `token` (string) — The final JWT token

**Type**

`Object`
