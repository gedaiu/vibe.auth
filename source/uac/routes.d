module uac.routes;

import vibe.http.router;
import vibe.data.json;
import uac.users;
import std.algorithm.searching, std.base64, std.string, std.stdio;

struct BasicAuthCredentials {
  string username;
  string password;
}

class UserOAuth2RequestHandler {

  private UserCollection collection;

  this(UserCollection collection) {
    this.collection = collection;
  }

  void checkLogin(scope HTTPServerRequest req, scope HTTPServerResponse res) {
    setAccessControl(res);

    if(req.method == HTTPMethod.OPTIONS) {
      return;
    }

    if(isTokenPath(req.path)) {
      doAuth(req, res);
    } else if(!isValidBearer(req)) {
      respondUnauthorized(res);
    }
  }

  private {

    bool isValidBearer(HTTPServerRequest req) {
      auto pauth = "Authorization" in req.headers;

      if(pauth && (*pauth).startsWith("Bearer ")) {
        auto token = (*pauth)[7 .. $];

        try {
          collection.byToken(token);
        } catch(UserNotFoundException exception) {
          return false;
        }

        return true;
      }

      return false;
    }

    void doAuth(scope HTTPServerRequest req, scope HTTPServerResponse res) {
      auto grantType = req.form["grant_type"];
      auto username = req.form["username"];
      auto password = req.form["password"];

      if(grantType == "password") {
        if(username in collection && collection[username].isValidPassword(password)) {
          Json response = Json.emptyObject;

          response.access_token = collection[username].createToken;
          response.token_type = "Bearer";
          response.expires_in = 3600;
          response.refresh_token = "";

          res.writeJsonBody(response);
        } else {
          respondUnauthorized(res, "Invalid password or username");
        }
      } else {
        respondUnauthorized(res, "Invalid `grant_type` value");
      }
    }

    void setAccessControl(ref HTTPServerResponse res) {
      res.headers["Access-Control-Allow-Origin"] = "*";
      res.headers["Access-Control-Allow-Headers"] = "Authorization, ";
    }

    bool isTokenPath(string path) {
      return path == "/auth/token";
    }

    BasicAuthCredentials parseBasicAuth(string data) {
      string decodedData = cast(string)Base64.decode(data);
      auto idx = decodedData.indexOf(":");
      enforceBadRequest(idx >= 0, "Invalid auth string format!");

      return BasicAuthCredentials(decodedData[0 .. idx], decodedData[idx+1 .. $]);
    }

    void respondUnauthorized(scope HTTPServerResponse res, string message = "Authorization required") {
      res.statusCode = HTTPStatus.unauthorized;
      res.contentType = "text/plain";
      res.bodyWriter.write(message);
    }
  }
}


class UserBasicRequestHandler(string realm) {

  private UserCollection collection;

  this(UserCollection collection) {
    this.collection = collection;
  }

  void checkLogin(scope HTTPServerRequest req, scope HTTPServerResponse res) {
    auto pauth = "Authorization" in req.headers;

    setAccessControl(res);

    if(pauth && (*pauth).startsWith("Basic ")) {
      auto auth = parseBasicAuth((*pauth)[6 .. $]);

      if(auth.username in collection && collection[auth.username].isValidPassword(auth.password)) {
        req.username = auth.username;
        return;
      } else {
        respondUnauthorized(res);
      }
    } else {
      respondUnauthorized(res);
    }
  }

  private {
    void setAccessControl(HTTPServerResponse res) {
      res.headers["Access-Control-Allow-Origin"] = "*";
      res.headers["Access-Control-Allow-Headers"] = "";
    }

    BasicAuthCredentials parseBasicAuth(string data) {
      string decodedData = cast(string)Base64.decode(data);
      auto idx = decodedData.indexOf(":");
      enforceBadRequest(idx >= 0, "Invalid auth string format!");

      return BasicAuthCredentials(decodedData[0 .. idx], decodedData[idx+1 .. $]);
    }

    void respondUnauthorized(scope HTTPServerResponse res, string message = "Authorization required") {
      res.statusCode = HTTPStatus.unauthorized;
      res.contentType = "text/plain";
      res.headers["WWW-Authenticate"] = "Basic realm=\""~realm~"\"";
      res.bodyWriter.write(message);
    }
  }
}

void registerUAC(string realm = "Unknown realm")(URLRouter router, UserCollection collection) {
  //auto handler = new UserBasicRequestHandler!realm(collection);
  auto oauth = new UserOAuth2RequestHandler(collection);

  router.any("*", &oauth.checkLogin);
  //router.any("*", &handler.checkLogin);
}
