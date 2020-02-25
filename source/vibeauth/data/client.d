/++
  A module containing the client structure

  Copyright: © 2018-2020 Szabo Bogdan
  License: Subject to the terms of the MIT license, as written in the included LICENSE.txt file.
  Authors: Szabo Bogdan
+/
module vibeauth.data.client;

import vibeauth.collections.base;
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
