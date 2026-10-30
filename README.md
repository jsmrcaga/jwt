# @control/jwt

A very simple JWT token generator & verifier

Exposes both a simple namespace full of functions to generate raw JWTs,
and a generator to manage multiple generations & validations from a
single generator key.

## Usage

### Raw tokens
```js
const { Token } = require('@control/jwt');

const token = Token.generate(
	{
		payload: {
			iss: 'my-application',
			user: {
				username: 'my_username'
			}
		}
	},
	process.env.JWT_SECRET_KEY,
	'HS256'
);

try {
	Token.verify(token, process.env.JWT_SECRET_KEY);
} catch(e) {
	console.error('Token validation failed', e);
}
```

### Generator
```js
const { TokenGenerator } = require('@control/jwt');

const generator = new TokenGenerator({
	secret_key: process.env.JWT_SECRET_KEY,
	iss: 'my-application',
	max_age: 3600 * 24, // in seconds
	alg: 'HS256'
});

const token1 = generator.generate({
	payload: {
		// iss, max_age, exp and jti will be auto-added
		user: {
			username: 'my_username'
		}
	}
});

const token2 = generator.generate({
	payload: {
		// iss, max_age, exp and jti will be auto-added
		user: {
			username: 'other_username'
		}
	}
});

generator.verify(token1);

try {
	generator.verify(token2, {
		allowed_issuers: ['another_issuer']
	})
} catch(e) {
	console.error('Token validation failed', e);
}
```
