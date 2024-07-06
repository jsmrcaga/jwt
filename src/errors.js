class TokenError extends Error {
	constructor(message, { reason=null , ...options } = {}){
		super(message, options);
		this.reason = reason;
	}
}

module.exports = {
	TokenError
};
