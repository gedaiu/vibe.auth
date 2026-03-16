module vibeauth.tests.protocols.basic.auth;

import std.datetime;
import std.base64;

import vibe.http.router;

import vibeauth.protocols.basic.auth;
import vibeauth.identity.usercollection;
import vibeauth.identity.user;

version(unittest) {
  import fluentasserts.vibe.request;
  import fluent.asserts;
  import vibeauth.identity.usermemory;

  alias TestBasicAuth = vibeauth.protocols.basic.auth.BasicAuth!"TestRealm";

  UserMemoryCollection collection;
  User user;
  TestBasicAuth auth;

  auto testRouter(bool requireLogin = true) {
    auto router = new URLRouter();

    collection = new UserMemoryCollection([]);
    user = new User("user@gmail.com", "password");
    user.firstName = "John";
    user.lastName = "Doe";
    user.username = "test";
    user.id = 1;

    collection.add(user);

    auth = new TestBasicAuth(collection);

    if (requireLogin) {
      router.any("*", &auth.mandatoryAuth);
    } else {
      router.any("*", &auth.permissiveAuth);
    }

    void handleRequest(HTTPServerRequest req, HTTPServerResponse res) {
      res.statusCode = 200;
      res.writeBody("Hello, World!");
    }

    router.get("/sites", &handleRequest);

    return router;
  }

  string encodeBasic(string username, string password) {
    return "Basic " ~ Base64.encode(cast(const(ubyte)[])(username ~ ":" ~ password)).idup;
  }
}

/// mandatory auth returns 401 on missing authorization header
unittest {
  testRouter.request.get("/sites").expectStatusCode(401).end();
}

/// mandatory auth returns 200 on valid base64 credentials
unittest {
  auto router = testRouter;

  router
    .request.get("/sites")
    .header("Authorization", encodeBasic("user@gmail.com", "password"))
    .expectStatusCode(200)
    .end;
}

/// mandatory auth returns 401 on invalid credentials
unittest {
  auto router = testRouter;

  router
    .request.get("/sites")
    .header("Authorization", encodeBasic("user@gmail.com", "wrongpassword"))
    .expectStatusCode(401)
    .end;
}

/// mandatory auth returns 401 on unknown user
unittest {
  auto router = testRouter;

  router
    .request.get("/sites")
    .header("Authorization", encodeBasic("nobody@test.com", "password"))
    .expectStatusCode(401)
    .end;
}

/// mandatory auth returns 401 on non-Basic authorization
unittest {
  auto router = testRouter;

  router
    .request.get("/sites")
    .header("Authorization", "Bearer sometoken")
    .expectStatusCode(401)
    .end;
}

/// permissive auth returns 401 on missing header
unittest {
  testRouter(false).request.get("/sites").expectStatusCode(401).end();
}

/// permissive auth returns 200 on valid credentials
unittest {
  auto router = testRouter(false);

  router
    .request.get("/sites")
    .header("Authorization", encodeBasic("user@gmail.com", "password"))
    .expectStatusCode(200)
    .end;
}
