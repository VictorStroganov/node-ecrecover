'use strict';

const expect = require('chai').expect;

const ecrecoverLib = require('../index');

describe('Тесты', function () {

	const containerName = "5973e5bc6-1e43-6206-c603-21fdd08867e";
	const passphrase = "";

	let hashSignatureForSourceMessage = "";

	let signatureForPreparedHash = "";

	let publicKeyBlob = {};

	let generatedSessionKey = {};

	let encryptionResult = {};
	let encryptionResult2 = {};


	it('Восстановление адреса по хешу и сигнатуре', async () => {

	    const hashHexN = "f5dabe3a125a6d7db1247b13a72e5f097b0032bf89601fe9a859469cc63a188d";
/*		let hashBytes = new Uint8Array( Buffer.from(hashHexN, 'hex') );
		hashBytes.reverse();
		hashHexN = Buffer.from(hashBytes).toString('hex');
		console.log(hashHexN);
*/
 //   	const pk = "d8d1dab36c5b660bbe73965e8125f6b267239fe559c58d1db61d5d872368fa219c2d9ed10b71445875859faa486beb139c75917d86cd46b47de32b099b94797c";
        const signRhexN = "50ac17a6faf7b6f293acb9526367b07a7fcbfea2e24234b2ad9058ec01702615";
        const signShexN = "d7b849ec83d8814097206e8d2884677a930d5e3f225618fb4046e1c6ed244dce";



		const hashHex = "52b52f1701e4294829d658c2c3bfbededf49426fc44185ebce7a59aba082305a";

		const signShex = "3b7b9b10d1d3d0c648f1385486885918153a2daed100ef63cdf359752f26f490";
		const signRhex = "18a36fd2476cad701311f929cbb0f5404751d4cf138ef19d9280e3be1c138e0b";
		const signV = 28;

		ecrecoverLib.setNodeContainer(containerName, passphrase);

		let recoveredAddress = ecrecoverLib.recoverAddress(hashHexN, signRhexN, signShexN, signV);

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

		expect(recoveredAddress).to.deep.equal("f1e340a1d2b691ee18dd962349cf2dee1571110d");
	});

	it('Вычисление адреса по публичному ключу', async () => {
		const publicKey = "90818e56a93e1ac3cf82467a6954236ca22772c3cd8256d618bbb332b2aa860f52a5ded5001f59eb62d01e596ff24f9fead5958f220b9175c31f5752dd02538b";

		let address = ecrecoverLib.getAddressByPublicKey(publicKey);

		expect(address).to.deep.equal("f1e340a1d2b691ee18dd962349cf2dee1571110d");
	});	
});