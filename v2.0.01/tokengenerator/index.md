---
title: TokenGenerator
kind: class
longname: TokenGenerator
description: TokenGenerator Allows generating JWT tokens from pre-set defaults. Useful in smaller applications
group: Utilities
---

# TokenGenerator

<SourceLink href="/source/jwt-js/#L224" label="jwt.js:224" />

TokenGenerator Allows generating JWT tokens from pre-set defaults. Useful in smaller applications

---

## Constructor

<Signature code="new TokenGenerator(init: Object): TokenGenerator" />

**Parameters**

- `init` (Object)
  - `init.secret_key` (string) — The secret key to use for this generator
  - `init.iss` (string) — The issuer, used as the `iss` claim in the JWT
  - `init.max_age` (string) — The max age of the token, in seconds
  - `init.alg` ([SignatureAlgorithm](/signaturealgorithm)) — The algorithm to use

---

## Instance Methods

<MemberHeading id="generatepayload" depth="3" name="generate_payload" sig="generate_payload(payload: Object): Object" />

<MemberMeta sourceHref="/source/jwt-js/#L250" sourceLabel="jwt.js:250" />

Generates the payload to use in JWT. Adds { max_age, iss, exp, jti }

- `exp` is taken from the passed payload or forced to \`null\`\`
- `jti` is a random UUID

**Parameters**

- `payload` (Object) — Extra payload. Overrides everythig else

**Returns**

- `Object`

<MemberHeading id="generate" depth="3" name="generate" sig="generate(params: Object)" />

<MemberMeta sourceHref="/source/jwt-js/#L266" sourceLabel="jwt.js:266" />

Generates a JWT, see `Token#generate`

**Parameters**

- `params` (Object)
  - `params.header` (Object) — Extra header to pass to `Token#generate`
  - `params.payload` (Object) — The payload for the token, uses [generate_payload](/tokengenerator#generatepayload)

<MemberHeading id="verify" depth="3" name="verify" sig="verify(token: string, params: Object): Object" />

<MemberMeta sourceHref="/source/jwt-js/#L286" sourceLabel="jwt.js:286" />

Verifies a token against the secret key, alg and mabye allowed_issuers

**Parameters**

- `token` (string) — The token to validate
- `params` (Object)
  - `params.allowed_issuers` (Array.\<string>) — The list of allowed issuers to validate

**Returns**

- `Object`

**Throws**

- `TokenError`

<MemberHeading id="create" depth="3" name="create" sig="create()" />

<MemberMeta sourceHref="/source/jwt-js/#L308" sourceLabel="jwt.js:308" />

Proxy function to `Token#create` passing this instance secret key and algorithm

<MemberHeading id="build" depth="3" name="build" sig="build()" />

<MemberMeta sourceHref="/source/jwt-js/#L315" sourceLabel="jwt.js:315" />

Proxy function to `Token#build` passing this instance secret key and algorithm
