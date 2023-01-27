import std.stdio;
import std.algorithm.searching : find;
import std.range : empty;
import kod;
import klic;

void main(string[] args) {
	// zpracovani argumentu
	auto rezim = "-t";
	foreach (zk; ["-t", "-g", "-d", "-h"]) {
		if (!args.find(zk).empty) {
			rezim = zk;
		}
	}

	auto encrypt = !args.find("-e").empty;
	auto soubor = "casaut.key";
	auto _zbytek = args.find("-k");
	if (!_zbytek.empty) {
		soubor = _zbytek[1];
	}

	switch (rezim) {
		case "-h":
			writeln("A client for time-based authentization written in D.");
			writeln("\nMODES:");
			writeln("-h\tprints the help");
			writeln("-g\tgenerates a new key");
			writeln("-t\tgenerates a code (token) using a key (the default)");
			writeln("-d\tdecrypts a key file that has been initially encrypted. Assumes -e");
			writeln("\nCONFIGURATION:");
			writeln("-k <file>\tsets the key file (casaut.key by default)");
			writeln("-e\tencrypts/decrypts the key using a symmetric cipher");
		break;
		case "-t":
			auto klic = nactiKlic(soubor, encrypt);
			writefln("Code: %s", generujKod(klic.dup));
			writefln("\n%d s left until the end of the time window", zbyvaDoKonce());
		break;
		case "-g":
			generujKlic(soubor, encrypt);
		break;
		case "-d":
			auto key = nactiKlic(soubor, true);
			auto file = File(soubor ~ ".raw", "wb");
			file.rawWrite(key);
			file.close;
			writefln("Key decrypted and saved to %s.raw", soubor);
		break;
		default: break;
	}
}

