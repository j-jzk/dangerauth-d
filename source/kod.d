import std.ascii : LetterCase;
import std.digest : toHexString;
import std.digest.sha : SHA256;
import std.string : representation;
import std.digest.hmac : hmac;
import std.datetime.systime;

private string casovyKod() {
	import std.conv : text;

	return text(Clock.currTime().toUnixTime() / 30);
}

int zbyvaDoKonce() {
	return 30 - Clock.currTime().toUnixTime() % 30;
}

string generujKod(immutable(ubyte[]) klic) {
	//auto hmac = retrieveMac("HMAC(SHA-256)");
	//hmac.setKey(klic);
	return casovyKod().representation.hmac!SHA256(klic).toHexString!(LetterCase.lower).dup;
}

