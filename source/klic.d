import std.stdio;
import botan.algo_base.symkey;
import std.digest.sha : sha256Of;
import memutils.refcounted : RefCounted;
import botan.rng.auto_rng : AutoSeededRNG;
import botan.libstate.lookup;

import botan.filters.pipe;

ubyte[] nactiKlic(string filename, bool encrypted) {
	auto file = File(filename, "rb");
	auto data = file.rawRead(new ubyte[file.size]);
	file.close();

	if (encrypted) {
		return decryptKey(data, nactiHeslo());
	} else {
		return data;
	}
}

void generujKlic(string filename, bool encrypt) {
	ubyte[512] key;
	auto rng = new AutoSeededRNG;
	rng.randomize(key.ptr, key.length);

	ubyte[] key2;
	if (encrypt) {
		key2 = zasifrujKlic(key, nactiHeslo());
	} else {
		key2 = key;
	}

	auto file = File(filename, "wb");
	file.rawWrite(key2);
	file.close();

	writefln("Key written to file %s", filename);
}

private ubyte[] zasifrujKlic(ubyte[] klic, SymmetricKey heslo) {
	ubyte[16] nonce;
	(new AutoSeededRNG).randomize(nonce.ptr, nonce.length);

	auto pipe = Pipe(getCipher(
		"Twofish/CBC/PKCS7",
		heslo,
		InitializationVector(nonce.ptr, nonce.length),
		ENCRYPTION
	));
	pipe.processMsg(klic.ptr, klic.length);

	auto msglen = pipe.remaining();
	ubyte[] vysl = new ubyte[nonce.length + msglen];
	
	vysl[0..nonce.length] = nonce[];
	pipe.read(vysl[nonce.length..$].ptr, msglen);

	return vysl;
}

private ubyte[] decryptKey(ubyte[] data, SymmetricKey password) {
	auto pipe = Pipe(getCipher(
		"Twofish/CBC/PKCS7",
		password,
		InitializationVector(data.ptr, 16),
		DECRYPTION
	));

	pipe.processMsg(data[16..$].ptr, data.length - 16);

	ubyte[] key = new ubyte[pipe.remaining()];
	pipe.read(key.ptr, key.length);
	return key;
}

private SymmetricKey nactiHeslo() {
	import core.stdc.stdlib : system;
	import std.string;

	write("Zadej heslo: ");

	version(Posix) system("stty -echo");
	auto heslo = readln().chomp();
	version(Posix) {
		system("stty echo");
		writeln();
	}

	auto sha = sha256Of(heslo);
	RefCounted!OctetStringImpl res = RefCounted!OctetStringImpl(sha.ptr, sha.length);
	return res;
}

