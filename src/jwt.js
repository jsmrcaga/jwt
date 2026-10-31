const Crypto = require('node:crypto');
const SignatureAlgorithms = require('./signature-algorithms');
const B64URL = require('./b64');
const { TokenError } = require('./errors');

const SUPPORTED_ALG = Object.keys(SignatureAlgorithms.sign);

/**
 * @category JWT
 * @class Token - A JWT token
 * This class is essentially a namespace for static functions
 */
class Token {
	/**
	 * Performs a JSON.stringify and encodes in utf8
	 * @static
	 * @param {Object} json - The object to stringify
	 * @returns string
	 */
	static stringify_utf8(json) {
		return Buffer.from(JSON.stringify(json)).toString('utf8');
	}

	/**
	 * @category JWT/Types
	 * @typedef {Object} JWTBuildParts
	 * @property {Object} header - The final header used for the token
	 * @property {string} b64_header - The header encoded in base 64
	 * @property {Object} payload - The final payload used for the JWT
	 * @property {string} b64_payload - The final payload encoded in base 64
	 * @property {string} signature - The signature of the token
	 * @property {string} token_wo_signature - The JWT token without the signature ("jose.payload" format)
	 * @property {string} token - The final JWT token
	 */

	/**
	 * Builds and returns all the pieces of a JWT
	 * @static
	 * @param {Object} params
	 * @param {Object} params.header - The payload to include in the JWT header. alg is implied from the arg, typ is always 'JWT'. Values here will override those two.
	 * @param {Object} params.payload - The JWT payload. No default values.
	 * @param {string} params.sk - The secret key
	 * @param {SignatureAlgorithm} alg
	 * @returns {JWTBuildParts} jwt_parts
	 */
	static build({ header: header_extra={}, payload={} }, sk, alg='HS256') {
		const b64_payload = B64URL.encode(this.stringify_utf8(payload));

		let header = {
			alg,
			typ: 'JWT',
			// Decided to leave the choice to the user
			// to make sure the validation works later
			...header_extra,
		};
		const b64_header = B64URL.encode(this.stringify_utf8(header));

		const token_wo_signature = `${b64_header}.${b64_payload}`;
		const signature = this.sign(token_wo_signature, sk, alg);

		const token = `${token_wo_signature}.${signature}`;
		return {
			header,
			b64_header,
			payload,
			b64_payload,
			signature,
			token_wo_signature,
			token
		};
	}

	/**
	 * Creates a token from raw values
	 * @static
	 * @param {Object} params
	 * @param {Object} params.header - Any payload to add to the token header
	 * @param {Object} params.payload - The payload for the token
	 * @param {string} sk - The secret key to use for signature
	 * @param {SignatureAlgorithm} alg - The signature algorithm to use
	 * @returns {string} - The JWT
	 */
	static create({ header={}, payload={} }, sk, alg='HS256') {
		const { token } = this.build({ header, payload }, sk, alg);
		return token;
	}

	/**
	 * Signs a given payload (in string) using a given secret key and algorith
	 * @static
	 * @param {string} str - The string payload
	 * @param {string} secret_key - The secret ey to use
	 * @param {SignatureAlgorithm} alg - The algorithm to use
	 * @returns {string} - The signature
	 */
	static sign(str, secret_key, alg='HS256') {
		return SignatureAlgorithms.sign[alg](str, secret_key);
	}

	/**
	 * @category JWT/Types
	 * @typedef {Object} JWTParts
	 * @property {string} header - The JWT header (b64)
	 * @property {Object} jose - The parsed header
	 * @property {Object} body - The parsed body
	 * @property {string} payload - The string body (b64)
	 * @property {string} signature - The signature (b64)
	 */

	/**
	 * Parses a jwt and returns the different pieces
	 * @static
	 * @param {string} token - The JWT to parse
	 * @returns {JWTParts}
	 */
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

	/**
	 * Verifies a jwt or throws.
	 * Checks for
	 * - invalid nbf (not before)
	 * - expired token (exp) (compared to Date.now() in seconds)
	 * - signature
	 * @param {string} jwt_string - The JWT in string format
	 * @param {string} sk - The secret key to use
	 * @throws {TokenError}
	 * @return {Object} The body of the jwt
	 */
	static verify(jwt_string, sk) {
		const { header, jose, payload, body, signature } = this.parse(jwt_string);

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

		const verification = SignatureAlgorithms.verify[alg](token_jose_and_payload, sk, signature);

		if(!verification) {
			throw new TokenError('Token: invalid signature');
		}

		return body;
	}

	// SK can be different things for every algo
	/**
	 * Generates a JWT with default values. Calls {@link create} under the hood
	 * @param {Object} params
	 * @param {Object} params.header - The header values to use, defaults will be overriden, see {@link create}
	 * @param {number} params.max_age - Max age for the token in seconds, if provided -> exp = Date.now()+ max_age 
	 * @param {Object} params.payload - The JWT payload, default is { exp=null, max_age=24h}
	 * @param {string} sk - The secret key to use for signature
	 * @param {SignatureAlgorithm} alg - The algorithm to use for signature
	 * @returns {string} The JWT itself
 	 */
	static generate({ header={}, max_age=3600*24, payload: { exp=null, iss, ...payload }}={}, sk, alg='HS256') {
		if(!SUPPORTED_ALG.includes(alg)) {
			throw new Error(`Unsupported algorithm ${alg}, only ${SUPPORTED_ALG.join(', ')} supported`);
		}

		const iat = Math.floor(Date.now() / 1000);
		const data = {
			iat,
			iss,
			// payload can overwrite any pre-computed properties
			...payload
		};

		if(exp || max_age) {
			data.exp = exp ?? iat + max_age;
		}

		return this.create({
			header,
			payload: data
		}, sk, alg);
	}
}

/**
 * @category Utilities
 * @class TokenGenerator
 * Allows generating JWT tokens from pre-set defaults. Useful in smaller applications
 */
class TokenGenerator {
	/**
	 * @param {Object} init
	 * @param {string} init.secret_key - The secret key to use for this generator
	 * @param {string} init.iss - The issuer, used as the `iss` claim in the JWT
	 * @param {string} init.max_age - The max age of the token, in seconds
	 * @param {SignatureAlgorithm} init.alg - The algorithm to use
	 */
	constructor({ secret_key, iss, max_age=null, alg='HS256' }) {
		if(!secret_key) {
			throw new Error('Cannot instanciate TokenGenerator without secret key.')
		}

		this.secret_key = secret_key;
		this.iss = iss;
		this.max_age = max_age;
		this.alg = alg;
	}

	/**
	 * Generates the payload to use in JWT. Adds { max_age, iss, exp, jti }
	 * - `exp` is taken from the passed payload or forced to `null``
	 * - `jti` is a random UUID
	 * @param {Object} payload - Extra payload. Overrides everythig else
	 * @returns {Object}
	 */
	generate_payload(payload={}) {
		return {
			iss: this.iss,
			exp: payload.exp || null,
			jti: Crypto.randomUUID(),
			...payload
		};
	}

	/**
	 * Generates a JWT, see {@link Token#generate}
	 * @param {Object} params
	 * @param {Object} params.header - Extra header to pass to {@link Token#generate}
	 * @param {Object} params.payload - The payload for the token, uses {@link generate_payload}
	 */
	generate({ header={}, max_age, payload={} }={}, alg=this.alg) {
		if(!SUPPORTED_ALG.includes(alg)) {
			throw new Error(`Unsupported algorithm ${alg}, only ${SUPPORTED_ALG.join(', ')} supported`);
		}

		const completed_payload = this.generate_payload(payload);
		const max_age_computed = Boolean(max_age) || max_age === null ? max_age : this.max_age;

		return Token.generate({
			header,
			max_age: max_age_computed,
			payload: completed_payload,
		}, this.secret_key, alg);
	}

	/**
	 * Verifies a token against the secret key, alg and mabye allowed_issuers
	 * @param {string} token - The token to validate
	 * @param {Object} params
	 * @param {string[]} params.allowed_issuers - The list of allowed issuers to validate
	 * @returns {Object} - The JWT body
	 * @throws {TokenError}
	 */
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

	/**
	 * Proxy function to {@link Token#create} passing this instance secret key and algorithm
	 */
	create({ header={}, payload={} }={}, alg=this.alg) {
		return Token.create({ header, payload }, this.secret_key, alg);
	}

	/**
	 * Proxy function to {@link Token#build} passing this instance secret key and algorithm
	 */
	build({ header={}, payload={} }={}, alg=this.alg) {
		return Token.build({ header, payload }, this.secret_key, alg);
	}
}


Token.TokenError = TokenError;
module.exports = { Token, TokenGenerator, B64URL };
