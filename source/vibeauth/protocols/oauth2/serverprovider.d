module vibeauth.protocols.oauth2.serverprovider;

import vibe.http.server;

interface AuthorizationServerProvider {
  string getAuthDomain(HTTPServerRequest req);
}

class DefaultAuthorizationServerProvider : AuthorizationServerProvider {
  private string domain;

  this(string domain) {
    this.domain = domain;
  }

  string getAuthDomain(HTTPServerRequest req) {
    return domain;
  }
}
