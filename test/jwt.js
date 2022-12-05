const fs = require('fs');
const path = require('path');
const { expect } = require('chai');

const DateFreeze = require('.//date-freeze');

const { Token, tokens, TokenGenerator, B64URL } = require('../src/jwt');

const PEM_RSA_SK = fs.readFileSync(path.join(__dirname, './keys/rsa/rsa-sk.pem'));
const PEM_RSA_PK = fs.readFileSync(path.join(__dirname, './keys/rsa/rsa-pk.pem'));

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
		it('Should generate a known token with HS256', () => {
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

		it('Should generate & verify a known token with RS256', () => {
			// Signature generated with RSA PEM keys on jwt.io
			const rsa_token = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2Mjg1MTQ5MDUsImV4cCI6MTYyODYwMTMwNSwiZGF0YSI6InBsZXAifQ.w_AsZMLZs6zMMRECEbemnk0XOljZ_AmyoNlaNndc4l95F-l5gng2lHygRKBYhFuiw4Cq-sUSb-ZdDlYEHABQFOOdy8p0ITK4LqC-mpD1ZUl5VyW3TnNadkFXsBjvPB_flVgGrUw-Ad9uA2bn7PvKS-v2IF8YMuJj_kE3oOSd4gD32I5volI2MtaSOdP8-BoaQdI2RtjTV6-DXubpFYKSCPWe11C5TynLMNCMIXwGr7-ZdxO6wCHtHPci6WB3ZF-qFL5MHbwafFZ21erCsnkOIzeE8gfYPH09LL__rVVS_59f7sAPfmFEe5gB3fva2yNpK1NywPhzHlhY2I7baX0P2A';
			DateFreeze.freeze(now);

			const token = Token.generate({
				data: 'plep'
			}, PEM_RSA_SK ,'RS256');


			expect(token).to.be.eql(rsa_token);
			expect(() => Token.verify(token, PEM_RSA_PK)).to.not.throw();
			expect(Token.verify(token, PEM_RSA_PK).data).to.be.eql('plep');
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
