module vibeauth.authenticators.EmberSimpleAuth;

import vibe.inet.url;
import vibe.http.router;
import vibe.http.server;
import vibe.data.json;

import vibeauth.authenticators.BaseAuth;
import vibeauth.router.responses;
import vibeauth.collections.usercollection;
import vibeauth.data.user;

import std.datetime;

/// Authentication using cookie storage for ember simple auth library.
/// http://ember-simple-auth.com/
class EmberSimpleAuth : BaseAuth {

  /// Instantiate the authenticator with an user collection
  this(UserCollection userCollection) {
    super(userCollection);
  }

  ///
  private AuthResult updateContext(HTTPServerRequest req, string bearer) {
    User user;

    try {
      user = collection.byToken(bearer);

      req.username = user.id;
      req.context["email"] = user.email;
    } catch(Exception) {
      return AuthResult.invalidToken;
    }

    return AuthResult.success;
  }

  override {
    /// Auth handler that will fail if a successfull auth was not performed.
    /// This handler is usefull for routes that want to hide information to the
    /// public.
    void mandatoryAuth(HTTPServerRequest req, HTTPServerResponse res) {
      super.mandatoryAuth(req, res);
    }

    /// ditto
    AuthResult mandatoryAuth(HTTPServerRequest req) {
      if(!req.hasValidEmberSession) {
        return AuthResult.unauthorized;
      }

      Json data = req.sessionData;

      if(data.type != Json.Type.object || "authenticated" !in data || "access_token" !in data["authenticated"]) {
        return AuthResult.unauthorized;
      }

      string bearer = data["authenticated"]["access_token"].to!string;

      return updateContext(req, bearer);
    }

    /// Auth handler that fails only if the auth fields are present and are not valid.
    /// This handler is usefull when a route should return different data when the user is
    /// logged in
    void permisiveAuth(HTTPServerRequest req, HTTPServerResponse res) {
      super.permisiveAuth(req, res);
    }

    /// ditto
    AuthResult permisiveAuth(HTTPServerRequest req) {
      if("ember_simple_auth-session" !in req.cookies) {
        return AuthResult.success;
      }

      Json data = req.sessionData;

      if(data.type != Json.Type.object) {
        return AuthResult.invalidToken;
      }

      if("authenticated" in data && "access_token" !in data["authenticated"]) {
        return AuthResult.success;
      }

      string bearer = data["authenticated"]["access_token"].to!string;
      return updateContext(req, bearer);
    }

    ///
    void respondUnauthorized(HTTPServerResponse res) {
      vibeauth.router.responses.respondUnauthorized(res);
    }

    ///
    void respondInvalidToken(HTTPServerResponse res) {
      vibeauth.router.responses.respondUnauthorized(res, "Invalid token.");
    }
  }
}

version(unittest) {
  import fluent.asserts;
  import vibeauth.data.token;
  import vibeauth.collections.usermemory;

  UserMemoryCollection collection;
  User user;

  EmberSimpleAuth auth;
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

    bearerToken = collection.createToken("user@gmail.com", Clock.currTime + 3600.seconds, ["doStuff"], "Bearer");

    auth = new EmberSimpleAuth(collection);

    if(requireLogin) {
      router.any("*", &auth.mandatoryAuth);
    } else {
      router.any("*", &auth.permisiveAuth);
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

/// with mandatory auth it should return 401 on missing cookie or useragent
unittest {
  testRouter.request.get("/sites").expectStatusCode(401).end();
}

/// with mandatory auth it should return 200 on valid credentials
unittest {
  auto router = testRouter;

  router
    .request.get("/sites")
    .header("User-Agent", "something")
    .header("Cookie", "ember_simple_auth-session=%7B%22authenticated%22%3A%7B%22access_token%22%3A%22" ~ bearerToken.name ~ "%22%7D%7D")
    .expectStatusCode(200)
    .end;
}

/// with mandatory auth it should return 401 on invalid credentials
unittest {
  auto router = testRouter;

  router
    .request.get("/sites")
    .header("User-Agent", "something")
    .header("Cookie", "ember_simple_auth-session=%7B%22authenticated%22%3A%7B%22access_token%22%3A%22%22%7D%7D")
    .expectStatusCode(401)
    .end;
}

/// with mandatory auth it should return 401 on missing access token
unittest {
  auto router = testRouter;

  router
    .request.get("/sites")
    .header("User-Agent", "something")
    .header("Cookie", "ember_simple_auth-session=%7B%22authenticated%22%3A%7B%7D%7D")
    .expectStatusCode(401)
    .end;
}

/// with mandatory auth it should return 401 on missing authenticated data
unittest {
  auto router = testRouter;

  router
    .request.get("/sites")
    .header("User-Agent", "something")
    .header("Cookie", "ember_simple_auth-session=%7B%22authenticated%22%3A%7B%7D%7D")
    .expectStatusCode(401)
    .end;
}

/// with mandatory auth it should return 401 on invalid json
unittest {
  auto router = testRouter;

  router
    .request.get("/sites")
    .header("User-Agent", "something")
    .header("Cookie", "ember_simple_auth-session=authenticated%22%3A%7B%7D%7D")
    .expectStatusCode(401)
    .end;
}

/// with mandatory auth it should set the email on valid credentials
unittest {
  testRouter
    .request.get("/email")
    .header("User-Agent", "something")
    .header("Cookie", "ember_simple_auth-session=%7B%22authenticated%22%3A%7B%22access_token%22%3A%22" ~ bearerToken.name ~ "%22%7D%7D")
    .expectStatusCode(200)
    .end((Response response) => {
      response.bodyString.should.equal("user@gmail.com");
    });
}

/// with permisive auth it should return 200 on missing cookie or useragent
unittest {
  testRouter(false).request.get("/sites").expectStatusCode(200).end();
}

/// with permisive auth it should return 401 on invalid json
unittest {
  testRouter(false)
    .request.get("/sites")
    .header("User-Agent", "something")
    .header("Cookie", "ember_simple_auth-session=authenticated%22%3A%7B%7D%7D")
    .expectStatusCode(401)
    .end;
}

/// with permisive auth it should return 401 on invalid credentials
unittest {
  testRouter(false)
    .request.get("/sites")
    .header("User-Agent", "something")
    .header("Cookie", "ember_simple_auth-session=%7B%22authenticated%22%3A%7B%22access_token%22%3A%22%22%7D%7D")
    .expectStatusCode(401)
    .end;
}

/// with permisive auth it should return 200 on missing user agent
unittest {
  testRouter(false)
    .request.get("/sites")
    .header("Cookie", "ember_simple_auth-session=%7B%22authenticated%22%3A%7B%22access_token%22%3A%22" ~ bearerToken.name ~ "%22%7D%7D")
    .expectStatusCode(200)
    .end;
}

/// with permisive auth it should return 200 on missing token
unittest {
  testRouter(false)
    .request.get("/sites")
    .header("Cookie", "ember_simple_auth-session%3D%7B%22authenticated%22%3A%7B%7D%7D")
    .expectStatusCode(200)
    .end;
}

/// with permisive auth it should return 200 on missing ember_simple_auth-session cookie
unittest {
  testRouter(false)
    .request.get("/sites")
    .header("User-Agent", "something")
    .expectStatusCode(200)
    .end;
}

/// with permisive auth it should return 200 on valid credentials
unittest {
  testRouter(false)
    .request.get("/sites")
    .header("User-Agent", "something")
    .header("Cookie", "ember_simple_auth-session=%7B%22authenticated%22%3A%7B%22access_token%22%3A%22" ~ bearerToken.name ~ "%22%7D%7D")
    .expectStatusCode(200)
    .end;
}

/// with permisive auth it should return 200 on missing authenticated keys
unittest {
  testRouter(false)
    .request.get("/sites")
    .header("User-Agent", "something")
    .header("Cookie", "ember_simple_auth-session=%7B%22authenticated%22%3A%7B%7D%7D")
    .expectStatusCode(200)
    .end;
}

/// with permisive auth it should set the email on valid credentials
unittest {
  testRouter(false)
    .request.get("/email")
    .header("User-Agent", "something")
    .header("Cookie", "ember_simple_auth-session=%7B%22authenticated%22%3A%7B%22access_token%22%3A%22" ~ bearerToken.name ~ "%22%7D%7D")
    .expectStatusCode(200)
    .end((Response response) => {
      response.bodyString.should.equal("user@gmail.com");
    });
}

/// Checks if the request contains the `ember_simple_auth-session` cookie and the `User-Agent` header is set
bool hasValidEmberSession(HTTPServerRequest req) {
  return "ember_simple_auth-session" in req.cookies && "User-Agent" in req.headers;
}

/// Extract the ember auth session data
Json sessionData(HTTPServerRequest req) {
  Json data = Json.emptyObject;

  try {
    data = req.cookies["ember_simple_auth-session"].parseJsonString;
  } catch(Exception) {
    return Json();
  }

  return data;
}