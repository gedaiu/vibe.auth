module vibeauth.tests.authenticators.OAuth2;

import std.datetime;

import vibe.data.json;
import vibe.http.router;

import vibeauth.authenticators.OAuth2;
import vibeauth.authenticators.oauth.AuthData;
import vibeauth.router.responses;
import vibeauth.router.accesscontrol;
import vibeauth.collections.usercollection;
import vibeauth.data.user;

version(unittest) {
  import fluentasserts.vibe.request;
  import fluentasserts.vibe.json;
  import fluent.asserts;
  import vibeauth.data.token;
  import vibeauth.collections.usermemory;

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
