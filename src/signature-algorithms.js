const Crypto = require('node:crypto');
const B64URL = require('./b64');
const { TokenError } = require('./errors');
// Each key should be a JOSE supported algorithm

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
