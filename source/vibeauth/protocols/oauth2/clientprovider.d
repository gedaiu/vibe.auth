module vibeauth.protocols.oauth2.clientprovider;

import vibe.data.json;

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

  /// Build the JSON a public consumer (e.g. the consent screen) should see for
  /// this client. Implementations decide which fields are safe to disclose and
  /// how metadata is rendered. `defaultClientPublicView` provides a sane default.
  Json publicView(Client client);
}

/// Reference rendering used by implementations that don't need to customize the
/// public shape. Exposes id/name/description/website/redirectUris/metadata.
Json defaultClientPublicView(Client client) {
  auto payload = Json.emptyObject;
  payload["id"] = client.id;
  payload["name"] = client.name;
  payload["description"] = client.description;
  payload["website"] = client.website;

  auto uris = Json.emptyArray;
  foreach(uri; client.redirectUris) {
    uris ~= Json(uri);
  }
  payload["redirectUris"] = uris;

  auto metadataJson = Json.emptyObject;
  foreach(key, value; client.metadata) {
    metadataJson[key] = value;
  }
  payload["metadata"] = metadataJson;

  return payload;
}
