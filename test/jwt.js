const fs = require('fs');
const path = require('path');
const { expect } = require('chai');

const DateFreeze = require('.//date-freeze');

const { Token, tokens, TokenGenerator, B64URL } = require('../src/jwt');

const PEM_RSA_SK = fs.readFileSync(path.join(__dirname, './keys/rsa/rsa-sk.pem'));
const PEM_RSA_PK = fs.readFileSync(path.join(__dirname, './keys/rsa/rsa-pk.pem'));

const PEM_EC_SK = fs.readFileSync(path.join(__dirname, './keys/ec/ec-sk.pkcs8.pem'));
const PEM_EC_PK = fs.readFileSync(path.join(__dirname, './keys/ec/ec-pk.pem'));

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
// jti: test-token
const example_token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2Mjg1MTQ5MDUsImlzcyI6Imlzc3Vlci1vbmUiLCJqdGkiOiJ0ZXN0LXRva2VuIiwiZGF0YSI6InBsZXAiLCJleHAiOjE2Mjg1MTg1MDV9.K3bfkieYYY2tumgFwI3QDmblv25qzviVkmKf71PURnU';

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
		it('Should generate a known token with HS256', () => {
			DateFreeze.freeze(now);

			const token = token_generator.generate({
				payload: {
					data: 'plep',
					jti: 'test-token'
				}
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

		it('Should generate a known token with HS256 + custom header values', () => {
			DateFreeze.freeze(now);

			const token = token_generator.generate({
				header: {
					url: 'http://google.com',
					nonce: 'random-string'
				},
				payload: {
					data: 'plep',
					jti: 'test-token'
				}
			});

			expect(token).to.be.eql('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsInVybCI6Imh0dHA6Ly9nb29nbGUuY29tIiwibm9uY2UiOiJyYW5kb20tc3RyaW5nIn0.eyJpYXQiOjE2Mjg1MTQ5MDUsImlzcyI6Imlzc3Vlci1vbmUiLCJqdGkiOiJ0ZXN0LXRva2VuIiwiZGF0YSI6InBsZXAiLCJleHAiOjE2Mjg1MTg1MDV9.5PGf_gMkTKdCrj2VB_UiY8vs0jK8zzRlD1vD_J-R_q4');
		});

		it('Should generate & verify a known token with RS256', () => {
			// Signature generated with RSA PEM keys on jwt.io
			const rsa_token = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2Mjg1MTQ5MDUsImRhdGEiOiJwbGVwIiwiZXhwIjoxNjI4NjAxMzA1fQ.pc9eNQ_abSBnk47by8tP1cdhV-obKPCwGu8ZrjakNhyIu-55XURwXbWeqpedsqk_Pd0oNXyjk3tmEH0QNuNuErXLNoSPEPLIOXMU3Ycrun_EksOBwhyrYWjNxDgeGIVJplm9RttOoGWo2GB1YifnutemG36iVagcvmtkrHeK-1YGIuopVQ-QszmX44qTVZvMWz_Y7y4JLvIJyZ_ki0T-h1nFrI_eBeV9ep3wtB4F57OiwMaJ0iInuvieltJVMwaWvzWDOfo-Gqb42FWO_mFi-RPluo75GIHwQV6a37XEzPYgsLvetZYiYvYJB9ZmB6-toy0LAA6ezrzXOxn9-Le3KA';
			DateFreeze.freeze(now);

			const token = Token.generate({
				payload: {
					data: 'plep'
				}
			}, PEM_RSA_SK ,'RS256');

			expect(token).to.be.eql(rsa_token);
			expect(() => Token.verify(token, PEM_RSA_PK)).to.not.throw();
			expect(Token.verify(token, PEM_RSA_PK).data).to.be.eql('plep');
		});

		it('Should generate & verify a known token with ES256', () => {
			// Signature generated with EC PEM/PKC8 keys on jwt.io
			const ec_token = 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2Mjg1MTQ5MDUsImV4cCI6MTYyODYwMTMwNSwiZGF0YSI6ImVjMjU2LXNpZ25lZCJ9.8kyotKuYwl6Rp3snNEdgpZYLfiOA-UOaRu7DaurZ4-H8P9XE2SrExjKvWt40-26G2lnlbm7eqCcNhFgAfoZYGQ';
			DateFreeze.freeze(now);

			const token = Token.generate({
				payload: {
					data: 'ec256-signed'
				}
			}, PEM_EC_SK ,'ES256');

			// Tokens cannot be equal because signatures are not consistent
			// they can change on every execution (tested by re-generating on jwt.io)
			expect(token).to.not.be.eql(ec_token);
			expect(() => Token.verify(token, PEM_EC_PK)).to.not.throw();
			expect(Token.verify(token, PEM_EC_PK).data).to.be.eql('ec256-signed');
		});

		it('Should verify a token', () => {
			DateFreeze.freeze(now);
			token_generator.verify(example_token);
		});

		it('Should raise because token is expired', () => {
			DateFreeze.freeze(now);
			const token = token_generator.generate({
				payload: {
					data: 'plep',
					exp: iat - 3600
				}
			});

			expect(() => token_generator.verify(token)).to.throw(Token.TokenError, /expired/);
		});

		it('Should raise because token is not yet valid', () => {
			DateFreeze.freeze(now);
			const token = token_generator.generate({
				payload: {
					data: 'plep',
					nbf: iat + 360000
				}
			});

			expect(() => token_generator.verify(token)).to.throw(Token.TokenError, /invalid nbf/);
		});

		it('Should raise because token signature is broken', () => {
			DateFreeze.freeze(now);
			const t = example_token.slice(0, example_token.length - 1);
			expect(() => token_generator.verify(t)).to.throw(Token.TokenError, /signature/);
		});

		it('Should raise because token issuer is not allowed', () => {
			const token = token_generator.generate({
				payload: {
					data: 'plep',
				}
			});

			expect(() => token_generator.verify(token, {
				allowed_issuers: ['plep']
			})).to.throw(Token.TokenError, /iss not allowed/);
		});

		it('Should generate a token without `exp`', () => {
			const token = Token.generate({
				max_age: null,
				payload: {
					iss: 'plep'
				}
			}, secret_key);

			const generator = new TokenGenerator({
				secret_key,
			});
			const token2 = generator.generate();

			for(const t of [token, token2]) {
				const { body } = Token.parse(t);
				expect(body).not.to.have.property('exp');
			}

			const generator_w_max_age = new TokenGenerator({
				secret_key,
				max_age: 3600
			});
			const token_w_max_age = generator_w_max_age.generate();
			const { body } = Token.parse(token_w_max_age);
			expect(body).to.have.property('exp');
		});
	});
})
