module vibeauth.router.oauth;

import vibe.http.router;
import vibe.data.json;
import vibeauth.users;
import vibe.inet.url;

import std.algorithm.searching, std.base64, std.string, std.stdio, std.conv;
import std.datetime;

import vibeauth.router.baseAuthRouter;
import vibeauth.client;
import vibeauth.collection;


struct OAuth2Configuration {
  string tokenPath = "/auth/token";
  string authorizePath = "/auth/authorize";
  string authenticatePath = "/auth/authenticate";
  string revokePath = "/auth/revoke";

  string style = "";
}

struct AuthData {
  string grantType;
  string username;
  string password;
  string[] scopes;
}

auto getAuthData(HTTPServerRequest req) {
  AuthData data;

  data.grantType = req.form["grant_type"];
  data.username = req.form["username"];
  data.password = req.form["password"];

  if("scope" in req.form) {
    data.scopes = req.form["scope"].split(" ");
  }

  return data;
}

class OAuth2: BaseAuthRouter {
  protected {
    const OAuth2Configuration configuration;
    ClientCollection clientCollection;
  }

  this(UserCollection userCollection, ClientCollection clientCollection, const OAuth2Configuration configuration = OAuth2Configuration()) {
    super(userCollection);

    this.configuration = configuration;
    this.clientCollection = clientCollection;
  }

  override {
    void checkLogin(HTTPServerRequest req, HTTPServerResponse res) {
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

        if(!res.headerWritten && req.path != configuration.style && !isValidBearer(req)) {
          respondUnauthorized(res);
        }
      } catch(Exception e) {
        version(unittest) {} else debug stderr.writeln(e);

        if(!res.headerWritten) {
          res.writeJsonBody([ "error": e.msg ], 500);
        }
      }
    }
  }

  void setAccessControl(ref HTTPServerResponse res) {
    if("Access-Control-Allow-Origin" !in res.headers) {
      res.headers["Access-Control-Allow-Origin"] = "*";
    } else {
      res.headers["Access-Control-Allow-Origin"] = ", *";
    }

    if("Access-Control-Allow-Headers" !in res.headers) {
      res.headers["Access-Control-Allow-Headers"] = "Authorization";
    } else {
      res.headers["Access-Control-Allow-Headers"] = ", Authorization";
    }
  }

  private {
    bool isValidBearer(HTTPServerRequest req) {
      auto pauth = "Authorization" in req.headers;

      if(pauth && (*pauth).startsWith("Bearer ")) {
        auto token = (*pauth)[7 .. $];

        try {
          auto const user = collection.byToken(token);
          req.username = user.email;
        } catch(UserNotFoundException exception) {
          return false;
        }

        return true;
      }

      return false;
    }

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

    private bool isValid(AuthData authData, HTTPServerResponse res) {
      if(authData.grantType != "password") {
        respondUnauthorized(res, "Invalid `grant_type` value");
        return false;
      }

      if(!collection.contains(authData.username)) {
        respondUnauthorized(res, "Invalid password or username");
        return false;
      }

      if(!collection[authData.username].isValidPassword(authData.password)) {
        respondUnauthorized(res, "Invalid password or username");
        return false;
      }

      return true;
    }

    void createToken(HTTPServerRequest req, HTTPServerResponse res) {
      auto authData = req.getAuthData;

      if(!isValid(authData, res)) {
        return;
      }

      Json response = Json.emptyObject;

      auto accessToken = collection.createToken(authData.username, Clock.currTime + 3601.seconds, authData.scopes);
      auto refreshToken = collection.createToken(authData.username, Clock.currTime + 30.weeks, [ "refresh" ]);

      response["access_token"] = accessToken.name;
      response["expires_in"] = (accessToken.expire - Clock.currTime).total!"seconds";
      response["token_type"] = accessToken.type;
      response["refresh_token"] = refreshToken.name;

      res.statusCode = 200;
      res.writeJsonBody(response);
    }

    void revoke(HTTPServerRequest req, HTTPServerResponse res) {
      auto const tokenType = req.form["token_type_hint"];
      auto const token = req.form["token"];

      respondUnauthorized(res, "Not implemented!");
    }

    void respondUnauthorized(HTTPServerResponse res, string message = "Authorization required") {
      res.statusCode = HTTPStatus.unauthorized;
      res.writeJsonBody([ "error": message ]);
    }
  }
}


version(unittest) {
  import http.request;
  import http.json;
  import bdd.base;

  UserMemmoryCollection collection;
  User user;
  Client client;
  ClientCollection clientCollection;
  OAuth2 auth;

  auto testRouter() {
    auto router = new URLRouter();

    collection = new UserMemmoryCollection(["doStuff"]);
  	user = new User("user", "password");
    user.id = 1;
  	collection.add(user);

    auto client = new Client();
    client.id = "CLIENT_ID";

    clientCollection = new ClientCollection([ client ]);

    auth = new OAuth2(collection, clientCollection);
    router.any("*", &auth.checkLogin);

    return router;
  }
}

@("it should return 401 on missing auth")
unittest {
  testRouter.request.get("/sites").expectStatusCode(401).end();
}

@("it should return 401 on invalid credentials")
unittest {
  testRouter
    .request.post("/auth/token")
    .send(["grant_type": "password", "username": "invalid", "password": "invalid"])
    .expectStatusCode(401)
    .end;
}

@("it should return tokens on valid credentials")
unittest {
  testRouter
    .request
    .post("/auth/token")
    .send(["grant_type": "password", "username": "user", "password": "password"])
    .expectStatusCode(200)
    .end((Response response) => {
      response.bodyJson.keys.should.contain(["access_token", "expires_in", "refresh_token", "token_type"]);

      user.isValidToken(response.bodyJson["access_token"].to!string).should.be.equal(true);
      user.isValidToken(response.bodyJson["refresh_token"].to!string).should.be.equal(true);

      response.bodyJson["token_type"].to!string.should.equal("Bearer");
      response.bodyJson["expires_in"].to!int.should.equal(3600);
    });
}


@("it should set the scope tokens on valid credentials")
unittest {
  testRouter
    .request
    .post("/auth/token")
    .send(["grant_type": "password", "username": "user", "password": "password", "scope": "access1 access2"])
    .expectStatusCode(200)
    .end((Response response) => {
      user.isValidToken(response.bodyJson["refresh_token"].to!string, "refresh").should.equal(true);
      user.isValidToken(response.bodyJson["refresh_token"].to!string, "other").should.equal(false);

      user.isValidToken(response.bodyJson["access_token"].to!string, "access1").should.equal(true);
      user.isValidToken(response.bodyJson["access_token"].to!string, "access2").should.equal(true);
      user.isValidToken(response.bodyJson["access_token"].to!string, "other").should.equal(false);
    });
}
