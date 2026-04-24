module vibeauth.tests.protocols.oauth2.auth;

import std.datetime;

import vibe.data.json;
import vibe.http.router;

import vibeauth.protocols.oauth2.auth;
import vibeauth.protocols.oauth2.authdata;
import vibeauth.protocols.oauth2.clientprovider;
import vibeauth.http.responses;
import vibeauth.http.accesscontrol;
import vibeauth.protocols.oauth2.clientprovider;
import vibeauth.identity.usercollection;
import vibeauth.identity.user;

version(unittest) {
  import fluentasserts.vibe.request;
  import fluentasserts.vibe.json;
  import fluent.asserts;
  import vibeauth.identity.token;
  import vibeauth.identity.usermemory;

  UserMemoryCollection collection;
  User user;
  OAuth2 auth;
  Token refreshToken;
  Token bearerToken;

  auto testRouter(bool requireLogin = true) {
    auto router = new URLRouter();

    collection = new UserMemoryCollection(["doStuff"]);
    user = new User("user@gmail.com", "password");
    user.firstName = "John";
    user.lastName = "Doe";
    user.username = "test";
    user.id = 1;

    collection.add(user);

    refreshToken = collection.createToken("user@gmail.com", Clock.currTime + 3600.seconds, ["doStuff", "refresh"], "Refresh");
    bearerToken = collection.createToken("user@gmail.com", Clock.currTime + 3600.seconds, ["doStuff"], "Bearer");

    auth = new OAuth2(collection);

    router.any("*", &auth.tokenHandlers);

    if(requireLogin) {
      router.any("*", &auth.mandatoryAuth);
    } else {
      router.any("*", &auth.permissiveAuth);
    }


    void handleRequest(HTTPServerRequest req, HTTPServerResponse res) {
      res.statusCode = 200;
      res.writeBody("Hello, World!");
    }

    void showEmail(HTTPServerRequest req, HTTPServerResponse res) {
      res.statusCode = 200;
      res.writeBody(req.context["email"].get!string);
    }

    router.get("/sites", &handleRequest);
    router.get("/email", &showEmail);

    return router;
  }
}

/// it should return 401 on missing auth
unittest {
  testRouter.request.get("/sites").expectStatusCode(401).end();
}

/// it should return 200 on valid credentials
unittest {
  auto router = testRouter;

  router
    .request.get("/sites")
    .header("Authorization", "Bearer " ~ bearerToken.name)
    .expectStatusCode(200)
    .end;
}

/// it should set the email on valid mandatory credentials
unittest {
  auto router = testRouter;

  router
    .request.get("/email")
    .header("Authorization", "Bearer " ~ bearerToken.name)
    .expectStatusCode(200)
    .end((Response response) => () {
      response.bodyString.should.equal("user@gmail.com");
    });
}

/// it should return 200 on missing auth when it's not mandatory
unittest {
  auto router = testRouter(false);

  router
    .request.get("/sites")
    .expectStatusCode(200)
    .end;
}

/// it should return 200 on valid auth when it's not mandatory
unittest {
  auto router = testRouter(false);

  router
    .request.get("/sites")
    .header("Authorization", "Bearer " ~ bearerToken.name)
    .expectStatusCode(200)
    .end;
}

/// it should set the email on valid credentials when they are not mandatory
unittest {
  auto router = testRouter(false);

  router
    .request.get("/email")
    .header("Authorization", "Bearer " ~ bearerToken.name)
    .expectStatusCode(200)
    .end((Response response) => () {
      response.bodyString.should.equal("user@gmail.com");
    });
}

/// it should return 401 on invalid auth when it's not mandatory
unittest {
  auto router = testRouter(false);

  router
    .request.get("/sites")
    .header("Authorization", "Bearer invalid")
    .expectStatusCode(400)
    .end;
}

/// it should return 401 on invalid credentials
unittest {
  testRouter
    .request.post("/auth/token")
    .send(["grant_type": "password", "username": "invalid", "password": "invalid"])
    .expectStatusCode(401)
    .end((Response response) => () {
      response.bodyJson.should.equal(`{ "error": "Invalid password or username" }`.parseJsonString);
    });
}

/// it should return tokens on valid email and password
unittest {
  testRouter
    .request
    .post("/auth/token")
    .send(["grant_type": "password", "username": "user@gmail.com", "password": "password"])
    .expectStatusCode(200)
    .end((Response response) => () {
      response.bodyJson.keys.should.contain(["access_token", "expires_in", "refresh_token", "token_type"]);

      user.isValidToken(response.bodyJson["access_token"].to!string).should.be.equal(true);
      user.isValidToken(response.bodyJson["refresh_token"].to!string).should.be.equal(true);

      response.bodyJson["token_type"].to!string.should.equal("Bearer");
      response.bodyJson["expires_in"].to!int.should.equal(3600);
    });
}

/// it should return tokens on valid username and password
unittest {
  testRouter
    .request
    .post("/auth/token")
    .send(["grant_type": "password", "username": "test", "password": "password"])
    .expectStatusCode(200)
    .end((Response response) => () {
      response.bodyJson.keys.should.contain(["access_token", "expires_in", "refresh_token", "token_type"]);

      user.isValidToken(response.bodyJson["access_token"].to!string).should.be.equal(true);
      user.isValidToken(response.bodyJson["refresh_token"].to!string).should.be.equal(true);

      response.bodyJson["token_type"].to!string.should.equal("Bearer");
      response.bodyJson["expires_in"].to!int.should.equal(3600);
    });
}

/// it should set the scope tokens on valid credentials
unittest {
  testRouter
    .request
    .post("/auth/token")
    .send(["grant_type": "password", "username": "user@gmail.com", "password": "password", "scope": "access1 access2"])
    .expectStatusCode(200)
    .end((Response response) => () {
      user.isValidToken(response.bodyJson["refresh_token"].to!string, "refresh").should.equal(true);
      user.isValidToken(response.bodyJson["refresh_token"].to!string, "other").should.equal(false);

      user.isValidToken(response.bodyJson["access_token"].to!string, "access1").should.equal(true);
      user.isValidToken(response.bodyJson["access_token"].to!string, "access2").should.equal(true);
      user.isValidToken(response.bodyJson["access_token"].to!string, "other").should.equal(false);
    });
}

/// it should return a new access token on refresh token
unittest {
  auto router = testRouter;

  router
    .request
    .post("/auth/token")
    .send(["grant_type": "refresh_token", "refresh_token": refreshToken.name ])
    .expectStatusCode(200)
    .end((Response response) => () {
      response.bodyJson.keys.should.contain(["access_token", "expires_in", "token_type"]);

      user.isValidToken(response.bodyJson["access_token"].to!string).should.be.equal(true);
      user.isValidToken(response.bodyJson["access_token"].to!string, "doStuff").should.be.equal(true);
      user.isValidToken(response.bodyJson["access_token"].to!string, "refresh").should.be.equal(false);

      response.bodyJson["token_type"].to!string.should.equal("Bearer");
      response.bodyJson["expires_in"].to!int.should.equal(3600);
    });
}

/// it should be able to not block the requests without login
unittest {
  auto router = testRouter(false);

  router
    .request
    .get("/path")
    .expectStatusCode(404)
    .end();
}

/// it should return 404 for GET on revocation path
unittest {
  auto router = testRouter(false);

  router
    .request
    .get("/auth/revoke")
    .expectStatusCode(404)
    .end();
}

/// it should return 400 for POST on revocation path with missing token
unittest {
  auto router = testRouter(false);

  router
    .request
    .post("/auth/revoke")
    .expectStatusCode(400)
    .end((Response response) => () {
      response.bodyJson.should.equal("{
        \"error\": \"You must provide a `token` parameter.\"
      }".parseJsonString);
    });
}

version(unittest) {
  import std.typecons;
  import vibeauth.protocols.oauth2.serverprovider;

  class TestClientProvider : ClientProvider {
    private Client[string] store;

    Client getClient(string clientId) {
      if (clientId == "known-client") {
        Client c;
        c.id = "known-client";
        c.name = "Test Client";
        c.redirectUris = ["http://localhost/cb"];
        return c;
      }

      if (clientId in store) {
        return store[clientId];
      }

      return Client.init;
    }

    Client registerClient(Client client) {
      if (client.id.length == 0) {
        client.id = "registered-" ~ client.name;
      }

      store[client.id] = client;
      return client;
    }

    Json publicView(Client client) {
      return defaultClientPublicView(client);
    }
  }

  TestClientProvider provider;

  auto testRouterWithClientProvider() {
    auto router = new URLRouter();

    collection = new UserMemoryCollection(["doStuff"]);
    user = new User("user@gmail.com", "password");
    user.firstName = "John";
    user.lastName = "Doe";
    user.username = "test";
    user.id = 1;

    collection.add(user);

    bearerToken = collection.createToken("user@gmail.com", Clock.currTime + 3600.seconds, ["doStuff"], "Bearer");

    auto serverProvider = new DefaultAuthorizationServerProvider("http://localhost");
    provider = new TestClientProvider();
    auth = new OAuth2(collection, OAuth2Configuration(), serverProvider, provider);

    router.any("*", &auth.tokenHandlers);
    router.any("*", &auth.permissiveAuth);

    return router;
  }
}

/// authorize returns 400 for unknown client_id when provider is set
unittest {
  auto router = testRouterWithClientProvider();

  router
    .request
    .get("/auth/authorize?client_id=unknown&redirect_uri=http://localhost&state=abc")
    .expectStatusCode(400)
    .end((Response response) => () {
      response.bodyJson["error"].get!string.should.equal("Unknown client_id");
    });
}

/// authorize redirects for known client_id when provider is set
unittest {
  auto router = testRouterWithClientProvider();

  router
    .request
    .get("/auth/authorize?client_id=known-client&redirect_uri=http://localhost/cb&state=abc")
    .expectStatusCode(302)
    .end();
}

/// authorize returns 400 when redirect_uri is not in the client's registered list
unittest {
  auto router = testRouterWithClientProvider();

  router
    .request
    .get("/auth/authorize?client_id=known-client&redirect_uri=http://evil.example.com/cb&state=abc")
    .expectStatusCode(400)
    .end((Response response) => () {
      response.bodyString.should.contain("Unregistered `redirect_uri`");
    });
}

/// authorize forwards the registered client_name as a query param on the login redirect
unittest {
  auto router = testRouterWithClientProvider();

  router
    .request
    .get("/auth/authorize?client_id=known-client&redirect_uri=http://localhost/cb&state=abc")
    .expectStatusCode(302)
    .end((Response response) => () {
      response.headers["Location"].should.contain("client_name=Test%20Client");
    });
}

/// authorize url-encodes the client_name so site URLs survive the round trip
unittest {
  auto router = testRouterWithClientProvider();

  router
    .request
    .post("/auth/register")
    .send(`{
      "client_name": "GISCollective WP Plugin @ http://192.168.1.190:8888",
      "redirect_uris": ["http://192.168.1.190:8888/wp-admin/admin.php?page=giscollective-settings"]
    }`.parseJsonString)
    .expectStatusCode(201)
    .end((Response response) => () {
      auto clientId = response.bodyJson["client_id"].get!string;

      router
        .request
        .get("/auth/authorize?client_id=" ~ clientId
          ~ "&redirect_uri=http://192.168.1.190:8888/wp-admin/admin.php?page=giscollective-settings&state=abc")
        .expectStatusCode(302)
        .end((Response authorizeResponse) => () {
          authorizeResponse.headers["Location"].should.contain(
            "client_name=GISCollective%20WP%20Plugin%20%40%20http%3A%2F%2F192.168.1.190%3A8888"
          );
        });
    });
}

/// authorizeComplete returns 400 for unknown client_id when provider is set
unittest {
  auto router = testRouterWithClientProvider();

  router
    .request
    .post("/auth/authorize/complete")
    .send(`{
      "email": "user@gmail.com",
      "password": "password",
      "client_id": "unknown",
      "redirect_uri": "http://localhost/cb",
      "state": "abc"
    }`.parseJsonString)
    .expectStatusCode(400)
    .end((Response response) => () {
      response.bodyJson["error"].get!string.should.equal("Unknown client_id");
    });
}


/// authorizeComplete returns 400 when redirect_uri is not in the client's registered list
unittest {
  auto router = testRouterWithClientProvider();

  router
    .request
    .post("/auth/authorize/complete")
    .send(`{
      "email": "user@gmail.com",
      "password": "password",
      "client_id": "known-client",
      "redirect_uri": "http://evil.example.com/cb",
      "state": "abc"
    }`.parseJsonString)
    .expectStatusCode(400)
    .end((Response response) => () {
      response.bodyJson["error"].get!string.should.equal("Unregistered redirect_uri for this client");
    });
}

/// register endpoint forwards metadata to the client provider
unittest {
  auto router = testRouterWithClientProvider();

  router
    .request
    .post("/auth/register")
    .send(`{
      "client_name": "Test App",
      "redirect_uris": ["http://localhost/cb"],
      "metadata": { "dataBindingId": "db-abc", "anythingElse": "value" }
    }`.parseJsonString)
    .expectStatusCode(201)
    .end((Response response) => () {
      auto clientId = response.bodyJson["client_id"].get!string;

      auto stored = provider.getClient(clientId);
      stored.metadata["dataBindingId"].should.equal("db-abc");
      stored.metadata["anythingElse"].should.equal("value");
    });
}

/// register endpoint stores client_name when present
unittest {
  auto router = testRouterWithClientProvider();

  router
    .request
    .post("/auth/register")
    .send(`{
      "client_name": "My App",
      "redirect_uris": ["http://localhost/cb"]
    }`.parseJsonString)
    .expectStatusCode(201)
    .end((Response response) => () {
      auto clientId = response.bodyJson["client_id"].get!string;
      response.bodyJson["client_name"].get!string.should.equal("My App");

      auto stored = provider.getClient(clientId);
      stored.name.should.equal("My App");
    });
}

/// register endpoint falls back to metadata.app_name when client_name is missing
unittest {
  auto router = testRouterWithClientProvider();

  router
    .request
    .post("/auth/register")
    .send(`{
      "redirect_uris": ["http://localhost/cb"],
      "metadata": { "app_name": "Via Metadata" }
    }`.parseJsonString)
    .expectStatusCode(201)
    .end((Response response) => () {
      auto clientId = response.bodyJson["client_id"].get!string;
      response.bodyJson["client_name"].get!string.should.equal("Via Metadata");

      auto stored = provider.getClient(clientId);
      stored.name.should.equal("Via Metadata");
    });
}

/// register endpoint falls back to software_id when client_name and metadata.app_name are missing
unittest {
  auto router = testRouterWithClientProvider();

  router
    .request
    .post("/auth/register")
    .send(`{
      "redirect_uris": ["http://localhost/cb"],
      "software_id": "com.example.app"
    }`.parseJsonString)
    .expectStatusCode(201)
    .end((Response response) => () {
      auto clientId = response.bodyJson["client_id"].get!string;
      response.bodyJson["client_name"].get!string.should.equal("com.example.app");

      auto stored = provider.getClient(clientId);
      stored.name.should.equal("com.example.app");
    });
}

/// register endpoint uses a default name when no name-like field is provided
unittest {
  auto router = testRouterWithClientProvider();

  router
    .request
    .post("/auth/register")
    .send(`{
      "redirect_uris": ["http://localhost/cb"]
    }`.parseJsonString)
    .expectStatusCode(201)
    .end((Response response) => () {
      auto clientId = response.bodyJson["client_id"].get!string;
      response.bodyJson["client_name"].get!string.should.equal("Unnamed OAuth client");

      auto stored = provider.getClient(clientId);
      stored.name.should.equal("Unnamed OAuth client");
    });
}

/// register endpoint treats whitespace-only client_name as missing and falls through
unittest {
  auto router = testRouterWithClientProvider();

  router
    .request
    .post("/auth/register")
    .send(`{
      "client_name": "   ",
      "redirect_uris": ["http://localhost/cb"],
      "metadata": { "app_name": "Real Name" }
    }`.parseJsonString)
    .expectStatusCode(201)
    .end((Response response) => () {
      auto clientId = response.bodyJson["client_id"].get!string;
      response.bodyJson["client_name"].get!string.should.equal("Real Name");

      auto stored = provider.getClient(clientId);
      stored.name.should.equal("Real Name");
    });
}

/// GET /auth/clients/<clientId> exposes the Client struct as JSON
unittest {
  auto router = testRouterWithClientProvider();

  router
    .request
    .get("/auth/clients/known-client")
    .expectStatusCode(200)
    .end((Response response) => () {
      response.bodyJson["id"].get!string.should.equal("known-client");
      response.bodyJson["name"].get!string.should.equal("Test Client");
    });
}

/// GET /auth/clients/<clientId> returns 404 for an unknown client
unittest {
  auto router = testRouterWithClientProvider();

  router
    .request
    .get("/auth/clients/does-not-exist")
    .expectStatusCode(404)
    .end();
}

/// authorizeComplete accepts an allowed expiresIn and the token endpoint honors it
unittest {
  import vibeauth.protocols.oauth2.codestore;
  auto router = testRouterWithClientProvider();

  router
    .request
    .post("/auth/authorize/complete")
    .send(`{
      "email": "user@gmail.com",
      "password": "password",
      "client_id": "known-client",
      "redirect_uri": "http://localhost/cb",
      "state": "abc",
      "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
      "code_challenge_method": "S256",
      "expiresIn": 2592000
    }`.parseJsonString)
    .expectStatusCode(200)
    .end((Response completeResponse) => () {
      auto code = completeResponse.bodyJson["code"].get!string;

      router
        .request
        .post("/auth/token")
        .send([
          "grant_type": "authorization_code",
          "code": code,
          "code_verifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
          "redirect_uri": "http://localhost/cb"
        ])
        .expectStatusCode(200)
        .end((Response response) => () {
          auto expiresIn = response.bodyJson["expires_in"].get!long;
          (expiresIn > 2592000 - 5 && expiresIn <= 2592000).should.equal(true);
        });
    });
}

/// authorizeComplete falls back to the legacy default when expiresIn is omitted
unittest {
  import vibeauth.protocols.oauth2.codestore;
  auto router = testRouterWithClientProvider();

  router
    .request
    .post("/auth/authorize/complete")
    .send(`{
      "email": "user@gmail.com",
      "password": "password",
      "client_id": "known-client",
      "redirect_uri": "http://localhost/cb",
      "state": "abc",
      "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
      "code_challenge_method": "S256"
    }`.parseJsonString)
    .expectStatusCode(200)
    .end((Response completeResponse) => () {
      auto code = completeResponse.bodyJson["code"].get!string;

      router
        .request
        .post("/auth/token")
        .send([
          "grant_type": "authorization_code",
          "code": code,
          "code_verifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
          "redirect_uri": "http://localhost/cb"
        ])
        .expectStatusCode(200)
        .end((Response response) => () {
          auto expiresIn = response.bodyJson["expires_in"].get!long;
          (expiresIn > defaultAccessTokenLifetime - 5 && expiresIn <= defaultAccessTokenLifetime).should.equal(true);
        });
    });
}

/// authorizeComplete rejects an expiresIn value outside the allowlist
unittest {
  auto router = testRouterWithClientProvider();

  router
    .request
    .post("/auth/authorize/complete")
    .send(`{
      "email": "user@gmail.com",
      "password": "password",
      "client_id": "known-client",
      "redirect_uri": "http://localhost/cb",
      "state": "abc",
      "expiresIn": 99
    }`.parseJsonString)
    .expectStatusCode(400)
    .end((Response response) => () {
      response.bodyJson["error"].get!string.should.equal("invalid_request");
    });
}

/// authorizeComplete rejects a negative expiresIn
unittest {
  auto router = testRouterWithClientProvider();

  router
    .request
    .post("/auth/authorize/complete")
    .send(`{
      "email": "user@gmail.com",
      "password": "password",
      "client_id": "known-client",
      "redirect_uri": "http://localhost/cb",
      "state": "abc",
      "expiresIn": -1
    }`.parseJsonString)
    .expectStatusCode(400)
    .end((Response response) => () {
      response.bodyJson["error"].get!string.should.equal("invalid_request");
    });
}

/// authorizeComplete rejects a non-integer expiresIn
unittest {
  auto router = testRouterWithClientProvider();

  router
    .request
    .post("/auth/authorize/complete")
    .send(`{
      "email": "user@gmail.com",
      "password": "password",
      "client_id": "known-client",
      "redirect_uri": "http://localhost/cb",
      "state": "abc",
      "expiresIn": "forever"
    }`.parseJsonString)
    .expectStatusCode(400)
    .end((Response response) => () {
      response.bodyJson["error"].get!string.should.equal("invalid_request");
    });
}

/// authorizeComplete rejects an expiresIn of 999999999 (the malicious-client scenario)
unittest {
  auto router = testRouterWithClientProvider();

  router
    .request
    .post("/auth/authorize/complete")
    .send(`{
      "email": "user@gmail.com",
      "password": "password",
      "client_id": "known-client",
      "redirect_uri": "http://localhost/cb",
      "state": "abc",
      "expiresIn": 999999999
    }`.parseJsonString)
    .expectStatusCode(400)
    .end((Response response) => () {
      response.bodyJson["error"].get!string.should.equal("invalid_request");
    });
}
