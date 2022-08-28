const { expect } = require('chai');

const DateFreeze = require('.//date-freeze');

const { Token, tokens, TokenGenerator, B64URL } = require('../src/jwt');

const secret_key = 'super-secret-key';
const iss = 'issuer-one';
const iat = 1628514905;
const max_age = 3600;
const exp = iat + max_age;

const token_generator = new TokenGenerator({
	secret_key,
	iss,
	max_age
});

const now = new Date(1628514905137);
const example_token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2Mjg1MTQ5MDUsImV4cCI6MTYyODUxODUwNSwiaXNzIjoiaXNzdWVyLW9uZSIsImRhdGEiOiJwbGVwIn0.E90zF73xO8jfBQPyXB_Wa8NObQgkhoU_S_wagqWzFVU';

describe('Base 64', () => {
	it('Should encode and replace non-url safe characters', () => {
		const unsafe_string = 'plep>>plepel???plop';
		// normal b64 'cGxlcD4+cGxlcGVsPz8/cGxvcA=='
		const expected_result = 'cGxlcD4-cGxlcGVsPz8_cGxvcA';
		const result = B64URL.encode(unsafe_string);
		expect(result).to.be.eql(expected_result);
	});
});

describe('Tokens', () => {
	afterEach(() => {
		DateFreeze.unfreeze();
	});

	describe('Token Generator', () => {
		it('Should generate a known token', () => {
			DateFreeze.freeze(now);

			const token = token_generator.generate({
				data: 'plep'
			});

			// Generated on jwt.io with
			/*
				{
					"alg": "HS256",
					"typ": "JWT"
				}
				{
					"iat": 1628514905,
					"exp": 1628518505,
					"iss": "issuer-one",
					"data": "plep"
				}
			*/
			// Note that signatures are not the same
			expect(token).to.be.eql(example_token);
		});

		it('Should verify a token', () => {
			DateFreeze.freeze(now);
			token_generator.verify(example_token);
		});

		it('Should raise because token is expired', () => {
			DateFreeze.freeze(now);
			const token = token_generator.generate({
				data: 'plep',
				exp: iat - 3600
			});

			expect(() => token_generator.verify(token)).to.throw(Token.TokenError, /expired/);
		});

		it('Should raise because token is not yet valid', () => {
			DateFreeze.freeze(now);
			const token = token_generator.generate({
				data: 'plep',
				nbf: iat + 360000
			});

			expect(() => token_generator.verify(token)).to.throw(Token.TokenError, /invalid nbf/);
		});

		it('Should raise because token signature is broken', () => {
			DateFreeze.freeze(now);
			const t = example_token.slice(0, example_token.length - 1);
			expect(() => token_generator.verify(t)).to.throw(Token.TokenError, /signature/);
		});
	});
})
