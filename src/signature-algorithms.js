const Crypto = require('node:crypto');
const B64URL = require('./b64');
const { TokenError } = require('./errors');
// Each key should be a JOSE supported algorithm

/**
 * @category JWT/Signature
 * @typedef {'HS256'|'RS256'|'ES256'} SignatureAlgorithm
 */

/**
 * @category JWT/Signature
 * @callback SignFunction
 * Creates a signature for the given payload under a set algorithm
 * @param {string} token - The token values to sign
 * @param {string} secret_key - The secret key to use
 * @returns {string} The signature
 */

/**
 * @category JWT/Signature
 * @callback SignatureValidationFunction
 * Validates a signature for the given payload under a set algorithm
 * @param {string} token_jose_and_payload - The token values to validate
 * @param {string} secret_key - The secret key to use
 * @param {string} signature - The signature to validate against
 * @returns {boolean} True if signature is valid
 */

/**
 * @category JWT/Signature
 * @type {{ sign: Record<SignatureAlgorithm, SignFunction>, verify: Record<SignatureAlgorithm, SignatureValidationFunction> }}
 */
const SignatureAlgorithms = {
	sign: {
		HS256: (token, secret_key) => {
			const hmac = Crypto.createHmac('sha256', secret_key);
			hmac.update(token);
			return hmac.digest('base64url');
		},
		RS256: (token, secret_key) => {
			const sign = Crypto.createSign('RSA-SHA256');
			sign.update(token);
			return sign.sign(secret_key).toString('base64url');
		},
		ES256: (token, secret_key) => {
			// For some reason it's the same, only the key-type changes
			return SignatureAlgorithms.sign.RS256(token, secret_key);
		}
	},
	verify: {
		HS256: (token_jose_and_payload, secret_key, signature) => {
			const hmac = Crypto.createHmac('sha256', secret_key);
			hmac.update(token_jose_and_payload);
			const computed_signature = hmac.digest('base64url');

			if(computed_signature !== signature) {
				throw new TokenError('Token: invalid signature');
			}

			return true;
		},
		RS256: (token_jose_and_payload, public_key, signature) => {
			const verifier = Crypto.createVerify('RSA-SHA256');
			verifier.update(token_jose_and_payload);
			return verifier.verify(public_key, signature, 'base64url');
		},
		ES256: (token_jose_and_payload, public_key, signature) => {
			return SignatureAlgorithms.verify.RS256(token_jose_and_payload, public_key, signature);
		}
	}
};

module.exports = SignatureAlgorithms;
