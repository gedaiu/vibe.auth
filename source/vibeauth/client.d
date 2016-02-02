module vibeauth.client;

import vibeauth.collection;

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
}
