module vibeauth.challenges.base;

public import vibe.http.router;
import std.datetime;

interface IChallenge {
	string generate(HTTPServerRequest req, HTTPServerResponse res);
	string getTemplate(string challangeLocation);
	bool validate(HTTPServerRequest req, HTTPServerResponse res, string response);
}

struct CodeEntry {
	SysTime time;
	string result;
}
