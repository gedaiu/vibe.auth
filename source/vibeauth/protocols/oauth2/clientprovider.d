module vibeauth.protocols.oauth2.clientprovider;

struct Client {
  string id;
  string name;
  string description;
  string website;
}

interface ClientProvider {
  /// it should return a Client with an empty id if the client is not found
  Client getClient(string clientId);
}
