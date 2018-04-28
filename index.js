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
	'RecoverAddress': [CallResult, ['string', 'string', 'string', byte]],
	'SetNodeContainer': [CallResult, ['string', 'string']],
	'Sign': [CallResult, ['string', 'string', 'string']]
});

module.exports = {
	/**
	 * Объект, содержащий параметры цифровой подписи
	 *
	 * @typedef {Object} Sign
	 * @property {String} signRhex Компонента r цифровой подписи хеша, строка в формате hex
	 * @property {String} signRhex Компонента s цифровой подписи хеша, строка в формате hex
	 * @property {Integer} signV Компонента v цифровой подписи хеша, целое число 27/28
	 */

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
	},
	/**
	 * Установка имени и pin-кода ключевого контейнера перед вызовом функции recoverAddress()
	 *
	 * @param {String} containerName Имя ключевого контейнера
	 * @param {String} passphrase pin-код ключевого кнотейнера
	 *
	 * @return {void}
	 */
	setNodeContainer: (containerName, passphrase) => {
		const result = ecrecoverLib.SetNodeContainer(containerName, passphrase);

		if(result.error) {
			throw new Error(result.error);
		} else {
			return result.result;
		}

	},
	/**
	 * Вычисление цифровой подписи хеша
	 *
	 * @param {String} container Имя ключевого контейнера
	 * @param {String} pin pin-код ключевого кнотейнера
	 * @param {String} hashHex Хеш, строка в формате hex
	 *
	 * @return {Sign} Параметры цифровой подписи
	 */
	sign: (container, pin, hashHex) => {
		const result = ecrecoverLib.Sign(container, pin, hashHex);

		if(result.error) {
			throw new Error(result.error);
		} else {
			const s = result.result.substr(64, 64);
			const r = result.result.substr(0, 64);
			const v = parseInt(result.result.substr(128, 2)) + 27;

			return {
				s: s,
				r: r,
				v: v
			};
		}
	}	
};
