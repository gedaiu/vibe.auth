module vibeauth.challenges.base;

public import vibe.http.router;

interface IChallenge {
  string generate(HTTPServerRequest req, HTTPServerResponse res);
  bool validate(HTTPServerRequest req, HTTPServerResponse res, string response);
}
