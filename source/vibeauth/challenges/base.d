module vibeauth.challenges.base;

public import vibe.http.router;
import std.datetime;

import vibe.data.json;

/// Interface for user challenge definition
interface IChallenge {
  /// Generate a challenge. The request must be initiated from the challenge template
  string generate(HTTPServerRequest req, HTTPServerResponse res);

  /// Get a template for the current challenge
  string getTemplate(string challangeLocation);

  /// Get config to create the html on client side
  Json getConfig();

  /// Validate the challenge
  bool validate(HTTPServerRequest req, HTTPServerResponse res, string response);
}

/// Secret code used to validate a challenge
struct CodeEntry {
  /// Time when the code was created
  SysTime time;

  /// The code value
  string result;
}
