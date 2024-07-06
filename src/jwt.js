const Crypto = require('node:crypto');
const SignatureAlgorithms = require('./signature-algorithms');
const B64URL = require('./b64');
const { TokenError } = require('./errors');

const SUPPORTED_ALG = Object.keys(SignatureAlgorithms.sign);

class Token {
	static stringify_utf8(json) {
		return Buffer.from(JSON.stringify(json)).toString('utf8');
	}

	static create({ header: header_extra, payload={} }, sk, alg='HS256') {
		const b64_payload = B64URL.encode(this.stringify_utf8(payload));

		let header = {
			alg,
			typ: 'JWT',
			// Decided to leave the choice to the user
			// to make sure the validation works later
			...header_extra,
		};
		header = B64URL.encode(this.stringify_utf8(header));

		const token_no_sign = `${header}.${b64_payload}`;
		const signature = this.sign(token_no_sign, sk, alg);

		return `${token_no_sign}.${signature}`;
	}

	static sign(str, secret_key, alg='HS256') {
		return SignatureAlgorithms.sign[alg](str, secret_key);
	}

	static parse(token) {
		const fragments = token.split('.');
		if(fragments.length !== 3) {
			throw new TokenError('Invalid number of fragments');
		}

		const [ header, payload, signature ] = fragments;

		const body = JSON.parse(B64URL.decode(payload));
		return {
			body,
			jose: JSON.parse(B64URL.decode(header)),
			header,
			payload,
			signature,
		};
	}

	static verify(data, keys) {
		const { header, jose, payload, body, signature } = this.parse(data);

		const now = (Date.now() / 1000);
		if(body.nbf && body.nbf > now) {
			throw new TokenError('Token: invalid nbf', {
				reason: {
					nbf: body.nbf,
					date: now
				}
			});
		}

		if(body.exp && body.exp < now) {
			throw new TokenError('Token: expired token', {
				reason: {
					exp: body.exp,
					date: now
				}
			});
		}

		const { alg } = jose;
		if(!(alg in SignatureAlgorithms.verify)) {
			throw new TokenError(`Signature algorithm not supported`, {
				reason: {
					alg,
					supported_algorithms: SUPPORTED_ALG
				}
			});
		}

		const token_jose_and_payload = `${header}.${payload}`;

		const verification = SignatureAlgorithms.verify[alg](token_jose_and_payload, keys, signature);

		if(!verification) {
			throw new TokenError('Token: invalid signature');
		}

		return body;
	}

	// SK can be different things for every algo
	static generate({ header={}, payload: { exp=null, max_age=3600*24, iss, ...payload }}={}, sk, alg='HS256') {
		if(!SUPPORTED_ALG.includes(alg)) {
			throw new Error(`Unsupported algorithm ${alg}, only ${SUPPORTED_ALG.join(', ')} supported`);
		}

		const iat = Math.floor(Date.now() / 1000);
		const data = {
			iat,
			exp: exp ?? iat + max_age,
			iss,
			// payload can overwrite any pre-computed properties
			...payload
		};

		return this.create({
			header,
			payload: data
		}, sk, alg);
	}
}

class TokenGenerator {
	constructor({ secret_key, iss, max_age, alg='HS256' }) {
		if(!secret_key) {
			throw new Error('Cannot instanciate TokenGenerator without secret key.')
		}

		this.secret_key = secret_key;
		this.iss = iss;
		this.max_age = max_age;
		this.alg = alg;
	}

	generate_payload(payload={}) {
		return {
			max_age: this.max_age,
			iss: this.iss,
			exp: payload.exp || null,
			jti: Crypto.randomUUID(),
			...payload
		};
	}

	generate({ header={}, payload={} }={}, alg=this.alg) {
		if(!SUPPORTED_ALG.includes(alg)) {
			throw new Error(`Unsupported algorithm ${alg}, only ${SUPPORTED_ALG.join(', ')} supported`);
		}

		const completed_payload = this.generate_payload(payload);
		return Token.generate({
			header,
			payload: completed_payload,
		}, this.secret_key, alg);
	}

	verify(token, {
		allowed_issuers
	} = {
		allowed_issuers: [this.iss]
	}) {
		const body = Token.verify(token, this.secret_key);

		if(!allowed_issuers.includes(body.iss)) {
			throw new TokenError('Token: iss not allowed', {
				details: {
					iss: body.iss,
					allowed_issuers
				}
			});
		}

		return body;
	}

	create({ header={}, payload={} }={}, alg=this.alg) {
		return Token.create({ header, payload }, this.secret_key, alg);
	}
}


Token.TokenError = TokenError;
module.exports = { Token, TokenGenerator, B64URL };
