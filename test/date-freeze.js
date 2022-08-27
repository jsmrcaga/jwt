const NativeDate = Date;

let frozen = null;

class DateFreeze extends Date {
	freeze(new_date) {
		frozen = new_date;
		global.Date = DateFreeze;
	}

	static now() {
		if(frozen) {
			return frozen.getTime();
		}

		return global.Date.now();
	}

	unfreeze() {
		frozen = null;
		global.Date = NativeDate;
	}
}

const freezer = new DateFreeze();

module.exports = freezer;
