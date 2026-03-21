/**
  OAuth 2.1 Protected Resource Metadata

  Implements RFC 9728 - OAuth 2.0 Protected Resource Metadata.
  Provides the metadata struct, configuration, and response helpers
  for OAuth 2.1 resource servers.

  This is protocol-agnostic and can be used by any OAuth 2.1 resource server
  (REST, MCP, GraphQL, etc.).

  See: https://datatracker.ietf.org/doc/html/rfc9728
*/
module vibeauth.protocols.oauth2.resource;

import vibe.http.server;
import vibe.http.common : HTTPStatus;
import vibe.data.json;
import vibe.core.log;

import std.string : format;
import std.array : join;

/**
  OAuth 2.1 Protected Resource Metadata.

  Served at /.well-known/oauth-protected-resource
*/
struct OAuthProtectedResourceMetadata {
  string resource = "";
  string issuer = "";
  string authorization_endpoint = "/auth/authorize";
  string token_endpoint = "/auth/token";
  string revocation_endpoint = "/auth/revoke";
  string registration_endpoint = "/auth/register";

  string[] response_types_supported = ["code"];
  string[] grant_types_supported = ["authorization_code", "refresh_token"];
  string[] code_challenge_methods_supported = ["S256"];
  string[] token_endpoint_auth_methods_supported = ["none"];
}

/**
  OAuth 2.1 configuration for a protected resource server.
*/
struct OAuth2ResourceConfig {
  /// Base URL of the OAuth 2.1 authorization server that issues tokens for this resource.
  /// Example: "https://auth.example.com"
  string authServerUrl;

  /// URL identifying this protected resource, included in WWW-Authenticate Bearer challenges.
  /// Example: "https://api.example.com"
  string resourceUrl;

  /// Optional issuer identifier to include in the protected resource metadata.
  /// If not set, defaults to the resourceUrl.
  /// Example: "https://auth.example.com"
  string issuer;

  /// OAuth scopes required to access this resource, advertised in WWW-Authenticate responses.
  /// Example: ["read", "write"] produces `scope="read write"` in the challenge.
  string[] scopes;
}

/**
  HTTP handler for the OAuth 2.1 Protected Resource Metadata endpoint.

  Serves metadata at /.well-known/oauth-protected-resource
*/
void handleProtectedResourceMetadata(OAuth2ResourceConfig config, HTTPServerRequest req, HTTPServerResponse res) {
  import vibe.core.path : InetPath;

  OAuthProtectedResourceMetadata metadata;

  auto reqUrl = req.fullURL;
  reqUrl.path = InetPath();
  string baseUrl = reqUrl.toString();

  metadata.resource = baseUrl;
  metadata.authorization_endpoint = baseUrl ~ "/auth/authorize";
  metadata.token_endpoint = baseUrl ~ "/auth/token";
  metadata.revocation_endpoint = baseUrl ~ "/auth/revoke";
  metadata.registration_endpoint = baseUrl ~ "/auth/register";

  metadata.issuer = config.issuer;
  if(!metadata.issuer) {
    metadata.issuer = metadata.resource;
  }



  res.headers["Content-Type"] = "application/json";
  res.headers["Cache-Control"] = "max-age=3600";
  res.writeJsonBody(metadata.serializeToJson());
}

/**
  Create a URLRouter handler for the protected resource metadata endpoint.
*/
auto protectedResourceMetadataHandler(OAuth2ResourceConfig config) {
  return (HTTPServerRequest req, HTTPServerResponse res) {
    handleProtectedResourceMetadata(config, req, res);
  };
}

/**
  Send OAuth 2.1 compliant 401 Unauthorized response.

  Includes WWW-Authenticate header with Bearer challenge and resource metadata URL
  per RFC 6750.
*/
void respondOAuth2Unauthorized(HTTPServerResponse res, OAuth2ResourceConfig config, string message = null) {
  auto challenge = format!"Bearer resource=\"%s\""(config.resourceUrl);

  if (config.scopes.length > 0) {
    challenge ~= format!" scope=\"%s\""(config.scopes.join(" "));
  }

  res.headers["WWW-Authenticate"] = challenge;
  res.headers["Content-Type"] = "application/json";

  Json errorBody = Json.emptyObject;
  errorBody["error"] = "unauthorized";

  if (message !is null) {
    errorBody["error_description"] = message;
  }

  res.writeJsonBody(errorBody, HTTPStatus.unauthorized);
}

version(unittest) {
  import fluent.asserts;
}

@("OAuthProtectedResourceMetadata serialization")
unittest {
  OAuthProtectedResourceMetadata metadata;
  metadata.resource = "https://resource.example.com";
  metadata.authorization_endpoint = "/auth/authorize";

  auto json = metadata.serializeToJson();
  json["resource"].should.equal("https://resource.example.com");
  json["authorization_endpoint"].should.equal("/auth/authorize");
}

@("OAuth2ResourceConfig WWW-Authenticate challenge format")
unittest {
  OAuth2ResourceConfig config;
  config.resourceUrl = "https://resource.example.com";
  config.scopes = ["read", "write"];

  auto challenge = format!"Bearer resource=\"%s\" scope=\"%s\""(
    config.resourceUrl,
    config.scopes.join(" ")
  );

  challenge.should.equal(`Bearer resource="https://resource.example.com" scope="read write"`);
}
