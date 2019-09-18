/++
  A module containing the token structure

  Copyright: © 2018 Szabo Bogdan
  License: Subject to the terms of the MIT license, as written in the included LICENSE.txt file.
  Authors: Szabo Bogdan
+/
module vibeauth.token;

import std.datetime;
import vibe.data.json;

/// A user token used to authorize the requests
struct Token {
  /// the token data
  string name;

  /// when the token should be deleted
  SysTime expire;

  /// the token scopes
  string[] scopes;

  /// the token type
  string type;

  /// some metadata
  @optional string[string] meta;
}
