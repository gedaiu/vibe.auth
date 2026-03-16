/++
  A module containing the client structure

  Copyright: © 2018-2020 Szabo Bogdan
  License: Subject to the terms of the MIT license, as written in the included LICENSE.txt file.
  Authors: Szabo Bogdan
+/
module vibeauth.identity.client;

import vibeauth.identity.collection;
import vibe.data.json;
import std.file;

/// Client app definition
class Client {
  /// The client Id
  string id;

  /// The client name
  string name;

  /// Short description
  string description;

  /// Client url
  string website;
}

version(unittest) {
  import fluent.asserts;
}

@("client fields are assignable")
unittest {
  auto c = new Client();
  c.id = "app1";
  c.name = "My App";
  c.description = "A test app";
  c.website = "https://example.com";

  c.id.should.equal("app1");
  c.name.should.equal("My App");
  c.description.should.equal("A test app");
  c.website.should.equal("https://example.com");
}
