module vibeauth.client;

import vibeauth.collection;
import vibe.data.json;
import std.file;

class Client {
  string id;
  string name;
  string description;
  string website;
}

class ClientCollection : Collection!Client {

  this(Client[] list) {
    super(list);
  }

  static ClientCollection FromFile(string path)
  {
    return new ClientCollection(path.readText.deserializeJson!(Client[]));
  }
}
