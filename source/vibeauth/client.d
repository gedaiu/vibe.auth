module vibeauth.client;

import vibeauth.collection;
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
