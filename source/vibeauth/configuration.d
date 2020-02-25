/++
  A module containing the configuration structures used to setup your auth process

  Copyright: © 2018 Szabo Bogdan
  License: Subject to the terms of the MIT license, as written in the included LICENSE.txt file.
  Authors: Szabo Bogdan
+/
module vibeauth.configuration;

import vibe.data.json;
import std.file;

version(unittest) {
  import fluent.asserts;
}

/// Structure used to define a service
struct ServiceConfiguration {
  /// The service name
  string name = "Unknown App";

  /// Login cookie expiration time
  ulong loginTimeoutSeconds = 86_400;
}
