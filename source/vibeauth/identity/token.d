/++
  A module containing the token structure

  Copyright: © 2018-2020 Szabo Bogdan
  License: Subject to the terms of the MIT license, as written in the included LICENSE.txt file.
  Authors: Szabo Bogdan
+/
module vibeauth.identity.token;

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

version(unittest) {
  import fluent.asserts;
}

@("token fields are assignable")
unittest {
  Token t;
  t.name = "abc123";
  t.expire = Clock.currTime + 3600.seconds;
  t.scopes = ["read", "write"];
  t.type = "Bearer";

  t.name.should.equal("abc123");
  t.scopes.length.should.equal(2);
  t.type.should.equal("Bearer");
}

@("optional meta defaults to null")
unittest {
  Token t;
  (t.meta is null).should.equal(true);

  t.meta = ["key": "value"];
  t.meta["key"].should.equal("value");
}
