class B64URL {
	static encode(data) {
		return Buffer.from(data).toString('base64url');
	}

	static decode(data) {
		return Buffer.from(data, 'base64url').toString('utf8');
	}
}

module.exports = B64URL;
