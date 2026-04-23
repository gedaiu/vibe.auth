module vibeauth.protocols.oauth2.clientprovider;

struct Client {
  string id;
  string name;
  string description;
  string website;
  string[] redirectUris;
  string[string] metadata;
}

interface ClientProvider {
  /// it should return a Client with an empty id if the client is not found
  Client getClient(string clientId);

  /// Register a new client and return it with a generated id
  Client registerClient(Client client);
}
