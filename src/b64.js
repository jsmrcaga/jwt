class B64URL {
	static encode(data) {
		const b64 = Buffer.from(data).toString('base64');
		return this.toURLB64(b64);
	}

	static toURLB64(b64str) {
		let b64 = b64str;
		const replacements = [
			[/=+$/g, ''],
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

module.exports = B64URL;
