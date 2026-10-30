---
title: SignatureValidationFunction
kind: typedef
longname: SignatureValidationFunction
group: JWT/Signature
---

# SignatureValidationFunction

<SourceLink href="/source/signature-algorithms-js/#L30" label="signature-algorithms.js:30" />

**Parameters**

- `token_jose_and_payload` (string) — The token values to validate
- `secret_key` (string) — The secret key to use
- `signature` (string) — The signature to validate against

**Returns**

- `boolean` — True if signature is valid
