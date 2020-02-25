module vibeauth.collections.client;

import vibeauth.collections.base;
import vibeauth.data.client;
import vibe.data.json;
import std.file;

/// Collection used to store the clients
class ClientCollection : Collection!Client {

  ///
  this(Client[] list) {
    super(list);
  }

  /// Create a client collection from a json file
  static ClientCollection FromFile(string path)
  {
    return new ClientCollection(path.readText.deserializeJson!(Client[]));
  }
}
