'use strict';

const expect = require('chai').expect;

const ecrecoverLib = require('../index');

describe('Тесты', function () {

	const hashForSourceMessage = new Uint8Array([82,181,47,23,1,228,41,72,41,214,88,194,195,191,190,222,223,73,66,111,196,65,133,235,206,122,89,171,160,130,48,90]);


	let hashSignatureForSourceMessage = "";

	let signatureForPreparedHash = "";

	let publicKeyBlob = {};

	let generatedSessionKey = {};

	let encryptionResult = {};
	let encryptionResult2 = {};

	it('Восстановление адреса по хешу и сигнатуре', async () => {
		const hashHex = "52b52f1701e4294829d658c2c3bfbededf49426fc44185ebce7a59aba082305a";

		const signShex = "3b7b9b10d1d3d0c648f1385486885918153a2daed100ef63cdf359752f26f490";
		const signRhex = "18a36fd2476cad701311f929cbb0f5404751d4cf138ef19d9280e3be1c138e0b";
		const signV = 28;

		let recoveredAddress = ecrecoverLib.recoverAddress(hashHex, signRhex, signShex, signV);

		expect(recoveredAddress).to.deep.equal("a59b15b2bf888c2d29f059079c556a3f3a805262");
	});

});