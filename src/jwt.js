const Crypto = require('crypto');

class TokenError extends Error {}

class B64URL {
	static encode(data) {
		const b64 = Buffer.from(data).toString('base64');
		return this.toURLB64(b64);
	}

	static toURLB64(b64str) {
		let b64 = b64str;
		const replacements = [
			[/=$/g, ''],
			[/\+/g, '-'],
			[/\//g, '_'],
		];

		for(const [from, to] of replacements) {
			b64 = b64.replace(from, to);
		}

		return b64;
	}

	static b64FromUrl(data) {
		let b64 = data.replace(/\-/g, '+');
		b64 = data.replace(/\_/g, '/');
		const remainder = b64.length % 4;
		if(!remainder) {
			return b64;
		}

		switch(remainder) {
			case 2:
				return `${b64}==`;
			case 3:
				return `${b64}=`;
			default:
				throw new Error('Illegal B64URL string');
		}
	}

	static decode(data) {
		const b64 = this.b64FromUrl(data);
		return Buffer.from(b64, 'base64').toString('utf8');
	}
}

class Token {
	static stringify_utf8(json) {
		return Buffer.from(JSON.stringify(json)).toString('utf8');
	}

	static create(payload, sk) {
		const b64_payload = B64URL.encode(this.stringify_utf8(payload));

		let header = {
			alg: 'HS256',
			typ: 'JWT'
		};
		header = B64URL.encode(this.stringify_utf8(header));

		let token_no_sign = `${header}.${b64_payload}`;
		let signature = this.sign(token_no_sign, sk);
		signature = B64URL.toURLB64(signature);

		return `${token_no_sign}.${signature}`;
	}

	static sign(str, secret_key) {
		const hmac = Crypto.createHmac('sha256', secret_key);
		hmac.update(str);
		return hmac.digest('base64');
	}

	static verify(data, sk) {
		const fragments = data.split('.');
		if(fragments.length !== 3) {
			throw new TokenError('Invalid number of fragments');
		}

		const [ header, payload, signature ] = fragments;

		const body = JSON.parse(B64URL.decode(payload));

		if(body.nbf && body.nbf > (Date.now() / 1000)) {
			throw new TokenError('Token: invalid nbf');
		}

		if(body.exp && body.exp < (Date.now() / 1000)) {
			throw new TokenError('Token: expired token');
		}

		const computed_signature = B64URL.toURLB64(this.sign(`${header}.${payload}`, sk));
		if(computed_signature !== signature) {
			throw new TokenError('Token: invalid signature');
		}

		return body;
	}

	static generate(payload={}, { exp=null, max_age=3600*24, iss }={}, sk) {
		const iat = Math.floor(Date.now() / 1000);
		const data = {
			iat,
			exp: exp ?? iat + max_age,
			iss,
			// payload can overwrite any pre-computed properties
			...payload
		};

		return this.create(data, sk);
	}
}

class TokenGenerator {
	constructor({ secret_key, iss, max_age }) {
		if(!secret_key) {
			throw new Error('Cannot instanciate TokenGenerator without secret key.')
		}

		this.secret_key = secret_key;
		this.iss = iss;
		this.max_age = max_age;
	}

	generate(payload={}) {
		return Token.generate(payload, {
			max_age: this.max_age,
			iss: this.iss,
			exp: payload.exp || null
		}, this.secret_key);
	}

	verify(token) {
		return Token.verify(token, this.secret_key);
	}

	create(payload={}) {
		return Token.create(payload, this.secret_key);
	}
}


Token.TokenError = TokenError;
module.exports = { Token, TokenGenerator };
