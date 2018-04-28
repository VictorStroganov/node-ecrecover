'use strict';

const expect = require('chai').expect;

const ecrecoverLib = require('../index');

describe('Тесты', function () {

	const hashForSourceMessage = new Uint8Array([82,181,47,23,1,228,41,72,41,214,88,194,195,191,190,222,223,73,66,111,196,65,133,235,206,122,89,171,160,130,48,90]);

	const containerName = "5973e5bc6-1e43-6206-c603-21fdd08867e";
	const passphrase = "";

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

		ecrecoverLib.setNodeContainer(containerName, passphrase);

		let recoveredAddress = ecrecoverLib.recoverAddress(hashHex, signRhex, signShex, signV);

		expect(recoveredAddress).to.deep.equal("a59b15b2bf888c2d29f059079c556a3f3a805262");
	});

/*	it('Генерация сигнатуры хеша', async () => {
		const hashHex = "52b52f1701e4294829d658c2c3bfbededf49426fc44185ebce7a59aba082305a";

		let sign = ecrecoverLib.sign(containerName, passphrase, hashHex);

		expect(sign).to.deep.equal("a59b15b2bf888c2d29f059079c556a3f3a805262");
	});*/

	it('Генерация сигнатуры хеша и восстановление параметров ключа', async () => {
		const hashHex = "52b52f1701e4294829d658c2c3bfbededf49426fc44185ebce7a59aba082305a";

		let sign = ecrecoverLib.sign(containerName, passphrase, hashHex);

		let recoveredAddress = ecrecoverLib.recoverAddress(hashHex, sign.r, sign.s, sign.v);

		console.log("recoveredAddress: " + recoveredAddress);

		expect(recoveredAddress).to.deep.equal("f1e340a1d2b691ee18dd962349cf2dee1571110d");
	});

	it('Вычисление адреса по публичному ключу', async () => {
		const publicKey = "90818e56a93e1ac3cf82467a6954236ca22772c3cd8256d618bbb332b2aa860f52a5ded5001f59eb62d01e596ff24f9fead5958f220b9175c31f5752dd02538b";

		let address = ecrecoverLib.getAddressByPublicKey(publicKey);

		expect(address).to.deep.equal("f1e340a1d2b691ee18dd962349cf2dee1571110d");
	});	
});