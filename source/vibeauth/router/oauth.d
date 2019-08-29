module vibeauth.router.oauth;

import vibe.http.router;
import vibe.data.json;
import vibe.inet.url;
import vibe.core.log;

import std.algorithm, std.base64, std.string, std.stdio, std.conv, std.array;
import std.datetime;

import vibeauth.users;
import vibeauth.router.baseAuthRouter;
import vibeauth.client;
import vibeauth.collection;

import vibeauth.router.responses;
import vibeauth.router.accesscontrol;

/// OAuth2 comfiguration
struct OAuth2Configuration {
  /// Route for generating tokens
  string tokenPath = "/auth/token";

  /// Route for authorization
  string authorizePath = "/auth/authorize";

  /// Route for authentication
  string authenticatePath = "/auth/authenticate";

  /// Route for revoking tokens
  string revokePath = "/auth/revoke";

  /// Custom style to be embeded into the html
  string style;
}

/// Struct used for user authentication
struct AuthData {
  ///
  string username;
  ///
  string password;
  ///
  string refreshToken;
  /// The authorization scopes
  string[] scopes;
}

///
interface IGrantAccess {
  /// setter for the authentication data
  void authData(AuthData authData);

  /// setter for the user collection
  void userCollection(UserCollection userCollection);

  /// validate the auth data
  bool isValid();

  /// get a Json response
  Json get();
}

/// Handle errors during token generation
final class UnknownGrantAccess : IGrantAccess {
  /// Ignores the auth data
  void authData(AuthData) {}

  /// Ignore the user collection
  void userCollection(UserCollection) {};

  /// All the requests are invalid
  bool isValid() {
    return false;
  }

  /// Get an error Json response
  Json get() {
    auto response = Json.emptyObject;
    response["error"] = "Invalid `grant_type` value";

    return response;
  }
}

/// Grant user access based on username and password strings
final class PasswordGrantAccess : IGrantAccess {
  private {
    AuthData data;
    UserCollection collection;
  }

  /// setter for the authentication data
  void authData(AuthData authData) {
    this.data = authData;
  }

  /// setter for the user collection
  void userCollection(UserCollection userCollection) {
    this.collection = userCollection;
  }

  /// validate the authentication data
  bool isValid() {
    if(!collection.contains(data.username)) {
      return false;
    }

    if(!collection[data.username].isValidPassword(data.password)) {
      return false;
    }

    return true;
  }

  /// Get the token Json response object
  Json get() {
    auto response = Json.emptyObject;

    if(!isValid) {
      response["error"] = "Invalid password or username";
      return response;
    }

    auto now = Clock.currTime;

    auto user = collection[data.username];
    foreach(token; user.getTokensByType("Bearer").array) {
      if(token.expire < now) {
        user.revoke(token.name);
      }
    }

    foreach(token; user.getTokensByType("Refresh").array) {
      if(token.expire < now) {
        user.revoke(token.name);
      }
    }


    auto accessToken = collection.createToken(data.username, Clock.currTime + 3601.seconds, data.scopes, "Bearer");
    auto refreshToken = collection.createToken(data.username, Clock.currTime + 30.weeks, data.scopes ~ [ "refresh" ], "Refresh");

    response["access_token"] = accessToken.name;
    response["expires_in"] = (accessToken.expire - Clock.currTime).total!"seconds";
    response["token_type"] = accessToken.type;
    response["refresh_token"] = refreshToken.name;

    return response;
  }
}

/// Grant user access based on a refresh token
final class RefreshTokenGrantAccess : IGrantAccess {
  private {
    AuthData data;
    UserCollection collection;
    User user;
  }

  /// setter for the authentication data
  void authData(AuthData authData) {
    this.data = authData;
    cacheData;
  }

  /// setter for the user collection
  void userCollection(UserCollection userCollection) {
    this.collection = userCollection;
    cacheData;
  }

  private void cacheData() {
    if(collection is null || data.refreshToken == "") {
      return;
    }

    user = collection.byToken(data.refreshToken);
    data.scopes = user.getScopes(data.refreshToken).filter!(a => a != "refresh").array;
  }

  /// Validate the refresh token
  bool isValid() {
    if(data.refreshToken == "") {
      return false;
    }

    return user.isValidToken(data.refreshToken, "refresh");
  }

  /// Get the token Json response object
  Json get() {
    auto response = Json.emptyObject;

    if(!isValid) {
      response["error"] = "Invalid `refresh_token`";
      return response;
    }

    auto username = user.email();

    auto accessToken = collection.createToken(username, Clock.currTime + 3601.seconds, data.scopes, "Bearer");

    response["access_token"] = accessToken.name;
    response["expires_in"] = (accessToken.expire - Clock.currTime).total!"seconds";
    response["token_type"] = accessToken.type;

    return response;
  }
}

/// Get the right access generator
IGrantAccess getAuthData(HTTPServerRequest req) {
  AuthData data;

  if("refresh_token" in req.form) {
    data.refreshToken = req.form["refresh_token"];
  }

  if("username" in req.form) {
    data.username = req.form["username"];
  }

  if("password" in req.form) {
    data.password = req.form["password"];
  }

  if("scope" in req.form) {
    data.scopes = req.form["scope"].split(" ");
  }

  if("grant_type" in req.form) {
    if(req.form["grant_type"] == "password") {
      auto grant = new PasswordGrantAccess;
      grant.authData = data;

      return grant;
    }

    if(req.form["grant_type"] == "refresh_token") {
      auto grant = new RefreshTokenGrantAccess;
      grant.authData = data;

      return grant;
    }
  }

  return new UnknownGrantAccess;
}

/// OAuth2 autenticator
class OAuth2: BaseAuthRouter {
  protected {
    const OAuth2Configuration configuration;
    ClientCollection clientCollection;
  }

  ///
  this(UserCollection userCollection, ClientCollection clientCollection, const OAuth2Configuration configuration = OAuth2Configuration()) {
    super(userCollection);

    this.configuration = configuration;
    this.clientCollection = clientCollection;
  }


  /// Handle the OAuth requests. Handles token creation, authorization
  /// authentication and revocation
  void tokenHandlers(HTTPServerRequest req, HTTPServerResponse res) {
    try {
      setAccessControl(res);
      if(req.method == HTTPMethod.OPTIONS) {
        return;
      }

      if(req.path == configuration.tokenPath) {
        createToken(req, res);
      }

      if (req.path == configuration.authorizePath) {
        authorize(req, res);
      }

      if(req.path == configuration.authenticatePath) {
        authenticate(req, res);
      }

      if(req.path == configuration.revokePath) {
        revoke(req, res);
      }
    } catch(Exception e) {
      version(unittest) {} else debug stderr.writeln(e);

      if(!res.headerWritten) {
        res.writeJsonBody([ "error": e.msg ], 500);
      }
    }
  }

  override {
    /// Auth handler that will fail if a successfull auth was not performed.
    /// This handler is usefull for routes that want to hide information to the
    /// public.
    void mandatoryAuth(HTTPServerRequest req, HTTPServerResponse res) {
      cleanRequest(req);

      try {
        setAccessControl(res);
        if(req.method == HTTPMethod.OPTIONS) {
          return;
        }

        if(!res.headerWritten && req.path != configuration.style && !isValidBearer(req)) {
          respondUnauthorized(res);
        }
      } catch(Exception e) {
        logError(e.toString);

        if(!res.headerWritten) {
          res.writeJsonBody([ "error": e.msg ], 400);
        }
      }
    }

    /// Auth handler that fails only if the auth fields are present and are not valid.
    /// This handler is usefull when a route should return different data when the user is
    /// logged in
    void permisiveAuth(HTTPServerRequest req, HTTPServerResponse res) {
      cleanRequest(req);

      if("Authorization" !in req.headers) {
        return;
      }

      mandatoryAuth(req, res);
    }
  }

  private {
    /// Remove all dangerous fields from the request
    void cleanRequest(HTTPServerRequest req) {
      req.username = "";
      req.password = "";
      if("email" in req.context) {
        req.context.remove("email");
      }
    }

    /// Validate the authorization token
    bool isValidBearer(HTTPServerRequest req) {
      auto pauth = "Authorization" in req.headers;

      if(pauth && (*pauth).startsWith("Bearer ")) {
        auto token = (*pauth)[7 .. $];

        try {
          auto const user = collection.byToken(token);
          req.username = user.id;
          req.context["email"] = user.email;

        } catch(UserNotFoundException exception) {
          return false;
        }

        return true;
      }

      return false;
    }

    /// Handle the authorization step
    void authorize(HTTPServerRequest req, HTTPServerResponse res) {
      if("redirect_uri" !in req.query) {
        showError(res, "Missing `redirect_uri` parameter");
        return;
      }

      if("client_id" !in req.query) {
        showError(res, "Missing `client_id` parameter");
        return;
      }

      if("state" !in req.query) {
        showError(res, "Missing `state` parameter");
        return;
      }

      auto const redirectUri = req.query["redirect_uri"];
      auto const clientId = req.query["client_id"];
      auto const state = req.query["state"];
      auto const style = configuration.style;

      if(clientId !in clientCollection) {
        showError(res, "Invalid `client_id` parameter");
        return;
      }

      string appTitle = clientCollection[clientId].name;

      res.render!("loginForm.dt", appTitle, redirectUri, state, style);
    }


    /// Show an HTML error
    void showError(HTTPServerResponse res, const string error) {
      auto const style = configuration.style;
      res.statusCode = 400;
      res.render!("error.dt", error, style);
    }

    void authenticate(HTTPServerRequest req, HTTPServerResponse res) {
      string email;
      string password;

      try {
        email = req.form["email"];
        password = req.form["password"];
      } catch (Exception e) {
        debug showError(res, e.to!string);
        return;
      }

      if(!collection.contains(email) || !collection[email].isValidPassword(password)) {
        showError(res, "Invalid email or password.");
        return;
      }

      auto token = collection[email].createToken(Clock.currTime + 3601.seconds);
      auto redirectUri = req.form["redirect_uri"] ~ "#access_token=" ~ token.name ~ "&state=" ~ req.form["state"];

      res.render!("redirect.dt", redirectUri);
    }

    /// Create token for the requested user
    void createToken(HTTPServerRequest req, HTTPServerResponse res) {
      auto grant = req.getAuthData;

      grant.userCollection = collection;
      res.statusCode = grant.isValid ? 200 : 401;
      res.writeJsonBody(grant.get);
    }

    /// Revoke a previously created token using a POST request
    void revoke(HTTPServerRequest req, HTTPServerResponse res) {
      if(req.method != HTTPMethod.POST) {
        return;
      }

      if("token" !in req.form) {
        res.statusCode = 400;
        res.writeJsonBody([ "error": "You must provide a `token` parameter." ]);

        return;
      }

      auto const token = req.form["token"];
      collection.revoke(token);

      res.statusCode = 200;
      res.writeBody("");
    }
  }
}

version(unittest) {
  import fluentasserts.vibe.request;
  import fluentasserts.vibe.json;
  import fluent.asserts;
  import vibeauth.token;

  UserMemmoryCollection collection;
  User user;
  Client client;
  ClientCollection clientCollection;
  OAuth2 auth;
  Token refreshToken;
  Token bearerToken;

  auto testRouter(bool requireLogin = true) {
    auto router = new URLRouter();

    collection = new UserMemmoryCollection(["doStuff"]);
    user = new User("user@gmail.com", "password");
    user.name = "John Doe";
    user.username = "test";
    user.id = 1;

    collection.add(user);

    refreshToken = collection.createToken("user@gmail.com", Clock.currTime + 3600.seconds, ["doStuff", "refresh"], "Refresh");
    bearerToken = collection.createToken("user@gmail.com", Clock.currTime + 3600.seconds, ["doStuff"], "Bearer");

    auto client = new Client();
    client.id = "CLIENT_ID";

    clientCollection = new ClientCollection([ client ]);

    auth = new OAuth2(collection, clientCollection);

    router.any("*", &auth.tokenHandlers);

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
    .end((Response response) => {
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

/// it should clear the username and email when auth it's not mandatory
unittest {
  auto router = testRouter(false);

  void setUser(HTTPServerRequest req, HTTPServerResponse res) {
    req.username = "some user";
    req.password = "some password";
    req.context["email"] = "some random value";
  }

  void showAuth(HTTPServerRequest req, HTTPServerResponse res) {
    res.statusCode = 200;
    string hasEmail = "email" in req.context ? "yes" : "no";
    res.writeBody(req.username ~ ":" ~ req.password ~ ":" ~ hasEmail);
  }

  router.any("*", &setUser);
  router.any("*", &auth.permisiveAuth);
  router.get("/misc", &showAuth);

  router
    .request.get("/misc")
    .expectStatusCode(200)
    .end((Response response) => {
      response.bodyString.should.equal("::no");
    });
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
    .end((Response response) => {
      response.bodyString.should.equal("user@gmail.com");
    });
}

/// it should return 401 on invalid auth when it's not mandatory
unittest {
  auto router = testRouter(false);

  router
    .request.get("/sites")
    .header("Authorization", "Bearer invalid")
    .expectStatusCode(401)
    .end;
}

/// it should return 401 on invalid credentials
unittest {
  testRouter
    .request.post("/auth/token")
    .send(["grant_type": "password", "username": "invalid", "password": "invalid"])
    .expectStatusCode(401)
    .end((Response response) => {
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
    .end((Response response) => {
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
    .end((Response response) => {
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
    .end((Response response) => {
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
    .end((Response response) => {
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
    .end((Response response) => {
      response.bodyJson.should.equal("{
        \"error\": \"You must provide a `token` parameter.\"
      }".parseJsonString);
    });
}
