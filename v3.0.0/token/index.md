---
title: Token
kind: class
longname: Token
description: Token - A JWT token This class is essentially a namespace for static functions
group: JWT
---

# Token

<SourceLink href="/source/jwt-js/#L13" label="jwt.js:13" />

Token - A JWT token This class is essentially a namespace for static functions

---

## Constructor

<Signature code="new Token(): Token" />

---

## Static Methods

<MemberHeading id="stringifyutf8" depth="3" name="stringify_utf8" sig="stringify_utf8(json: Object)" />

<MemberMeta badges="static" sourceHref="/source/jwt-js/#L20" sourceLabel="jwt.js:20" />

Performs a JSON.stringify and encodes in utf8

**Parameters**

- `json` (Object) — The object to stringify

**Returns**

- string

<MemberHeading id="build" depth="3" name="build" sig="build(params: Object, alg: SignatureAlgorithm): JWTBuildParts" />

<MemberMeta badges="static" sourceHref="/source/jwt-js/#L46" sourceLabel="jwt.js:46" />

Builds and returns all the pieces of a JWT

**Parameters**

- `params` (Object)
  - `params.header` (Object) — The payload to include in the JWT header. alg is implied from the arg, typ is always 'JWT'. Values here will override those two.
  - `params.payload` (Object) — The JWT payload. No default values.
  - `params.sk` (string) — The secret key
- `alg` ([SignatureAlgorithm](/signaturealgorithm))

**Returns**

- [`JWTBuildParts`](/jwtbuildparts) — jwt_parts

<MemberHeading
  id="create"
  depth="3"
  name="create"
  sig="create(
	params: Object,
	sk: string,
	alg: SignatureAlgorithm,
): string"
/>

<MemberMeta badges="static" sourceHref="/source/jwt-js/#L83" sourceLabel="jwt.js:83" />

Creates a token from raw values

**Parameters**

- `params` (Object)
  - `params.header` (Object) — Any payload to add to the token header
  - `params.payload` (Object) — The payload for the token
- `sk` (string) — The secret key to use for signature
- `alg` ([SignatureAlgorithm](/signaturealgorithm)) — The signature algorithm to use

**Returns**

- `string`

<MemberHeading
  id="sign"
  depth="3"
  name="sign"
  sig="sign(
	str: string,
	secret_key: string,
	alg: SignatureAlgorithm,
): string"
/>

<MemberMeta badges="static" sourceHref="/source/jwt-js/#L96" sourceLabel="jwt.js:96" />

Signs a given payload (in string) using a given secret key and algorith

**Parameters**

- `str` (string) — The string payload
- `secret_key` (string) — The secret ey to use
- `alg` ([SignatureAlgorithm](/signaturealgorithm), default: "HS256") — The algorithm to use

**Returns**

- `string`

<MemberHeading id="parse" depth="3" name="parse" sig="parse(token: string): JWTParts" />

<MemberMeta badges="static" sourceHref="/source/jwt-js/#L116" sourceLabel="jwt.js:116" />

Parses a jwt and returns the different pieces

**Parameters**

- `token` (string) — The JWT to parse

**Returns**

- [`JWTParts`](/jwtparts)

<MemberHeading id="verify" depth="3" name="verify" sig="verify(jwt_string: string, sk: string): Object" />

<MemberMeta badges="static" sourceHref="/source/jwt-js/#L145" sourceLabel="jwt.js:145" />

Verifies a jwt or throws. Checks for

- invalid nbf (not before)
- expired token (exp) (compared to Date.now() in seconds)
- signature

**Parameters**

- `jwt_string` (string) — The JWT in string format
- `sk` (string) — The secret key to use

**Returns**

- `Object` — The body of the jwt

**Throws**

- `TokenError`

<MemberHeading
  id="generate"
  depth="3"
  name="generate"
  sig="generate(
	params: Object,
	sk: string,
	alg: SignatureAlgorithm,
): string"
/>

<MemberMeta badges="static" sourceHref="/source/jwt-js/#L199" sourceLabel="jwt.js:199" />

Generates a JWT with default values. Calls `create` under the hood

**Parameters**

- `params` (Object)
  - `params.header` (Object) — The header values to use, defaults will be overriden, see `create`
  - `params.max_age` (number) — Max age for the token in seconds, if provided -> exp = Date.now()+ max_age
  - `params.payload` (Object) — The JWT payload, default is { exp=null, max_age=24h}
- `sk` (string) — The secret key to use for signature
- `alg` ([SignatureAlgorithm](/signaturealgorithm)) — The algorithm to use for signature

**Returns**

- `string` — The JWT itself
