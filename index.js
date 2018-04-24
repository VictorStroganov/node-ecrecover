'use strict';
const Path = require('path');

const pathToEcrecover = Path.resolve(__dirname, '.');

let pathToEcrecoverLib = '';

if(process.platform == 'win32') {
	pathToEcrecoverLib = pathToEcrecover + '/lib/ecrecover.dll';
} else {
	pathToEcrecoverLib = pathToEcrecover + '/lib/ecrecover.so';
}

const ffi = require('ffi');
const ref = require('ref');

//var ArrayType = require('ref-array');
var byte = ref.types.byte;
//var ByteArray = ArrayType(byte);

var Struct = require('ref-struct');

var CallResult = Struct({
	'result': 'string',
	'error': 'string'
});

const ecrecoverLib = ffi.Library(pathToEcrecoverLib, {
	'RecoverAddress': [CallResult, ['string', 'string', 'string', byte]]
});

module.exports = {
	/**
	 * Получение адреса по цифровой подписи хеша
	 *
	 * @param {String} hash Хеш, строка в формате hex
	 * @param {String} signRhex Компонента r цифровой подписи хеша, строка в формате hex
	 * @param {String} signRhex Компонента s цифровой подписи хеша, строка в формате hex
	 * @param {Integer} signV Компонента v цифровой подписи хеша, целое число 27/28
	 *
	 * @return {String} Восстановленный адрес, строка в формате hex
	 */
	recoverAddress: (hashHex, signRhex, signShex, signV) => {
		const result = ecrecoverLib.RecoverAddress(hashHex, signRhex, signShex, signV);

		if(result.error) {
			throw new Error(result.error);
		} else {
			return result.result;
		}
	}
};
