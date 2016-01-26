module uac.router.oauth;

import vibe.http.router;
import vibe.data.json;
import uac.users;
import std.algorithm.searching, std.base64, std.string, std.stdio;
import uac.router.baseAuthRouter;

class OAuth2: BaseAuthRouter {

  this(UserCollection collection) {
    super(collection);
  }

  override {
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
  }

  void setAccessControl(ref HTTPServerResponse res) {
    res.headers["Access-Control-Allow-Origin"] = "*";
    res.headers["Access-Control-Allow-Headers"] = "Authorization, ";
  }

  private {

    bool isValidBearer(HTTPServerRequest req) {
      auto pauth = "Authorization" in req.headers;

      if(pauth && (*pauth).startsWith("Bearer ")) {
        auto token = (*pauth)[7 .. $];

        try {
          auto user = collection.byToken(token);
          req.username = user.email;
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

      writeln("==>", username, " ", password, " ", username in collection);


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

    bool isTokenPath(string path) {
      return path == "/auth/token";
    }

    void respondUnauthorized(scope HTTPServerResponse res, string message = "Authorization required") {
      res.statusCode = HTTPStatus.unauthorized;
      res.contentType = "text/plain";
      res.bodyWriter.write(message);
    }
  }
}
