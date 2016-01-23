module uac.router.basic;

import vibe.http.router;
import vibe.data.json;
import uac.users;
import std.algorithm.searching, std.base64, std.string, std.stdio;
import uac.router.baseAuthRouter;

struct BasicAuthCredentials {
  string username;
  string password;
}

class BasicAuth(string realm): BaseAuthRouter {

  this(UserCollection collection) {
    super(collection);
  }

  override {
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
  }

  private {
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
