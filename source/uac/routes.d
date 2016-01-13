module uac.routes;

import vibe.http.router;
import uac.users;
import std.algorithm.searching, std.base64, std.string, std.stdio;

struct BasicAuthCredentials {
  string username;
  string password;
}

class UserRequestHandler(string realm) {

  private UserCollection collection;

  this(UserCollection collection) {
    this.collection = collection;
  }

  void checkLogin(scope HTTPServerRequest req, scope HTTPServerResponse res) {
    auto pauth = "Authorization" in req.headers;

    if(pauth && (*pauth).startsWith("Basic ")) {
      auto auth = parseBasicAuth((*pauth)[6 .. $]);

      if(auth.username in collection && collection[auth.username].isValidPassword(auth.password)) {
        auto token = collection[auth.username].createToken;
        res.headers["Token"] = token;

        return;
      } else {
        respondUnauthorized(res);
      }
    } else if(pauth && (*pauth).startsWith("Token ")) {
      try {
        auto token = (*pauth)[6 .. $];
        collection.byToken(token);
      } catch (UserNotFoundException e){
        respondUnauthorized(res);
      }
    } else {
      respondUnauthorized(res);
    }
  }

  private {
    BasicAuthCredentials parseBasicAuth(string data) {
      string decodedData = cast(string)Base64.decode(data);
      auto idx = decodedData.indexOf(":");
      enforceBadRequest(idx >= 0, "Invalid auth string format!");

      return BasicAuthCredentials(decodedData[0 .. idx], decodedData[idx+1 .. $]);
    }

    void respondUnauthorized(scope HTTPServerResponse res) {
      res.statusCode = HTTPStatus.unauthorized;
      res.contentType = "text/plain";
      res.headers["WWW-Authenticate"] = "Basic realm=\""~realm~"\"";
      res.bodyWriter.write("Authorization required");
    }
  }
}

void registerUAC(string realm = "Unknown realm")(URLRouter router, UserCollection collection) {
  auto handler = new UserRequestHandler!realm(collection);
/*
	void handleRequest(scope HTTPServerRequest req, scope HTTPServerResponse res)
	{
		auto pauth = "Authorization" in req.headers;

		if( pauth && (*pauth).startsWith("Basic ") ) {
			string user_pw = cast(string)Base64.decode((*pauth)[6 .. $]);

			auto idx = user_pw.indexOf(":");
			enforceBadRequest(idx >= 0, "Invalid auth string format!");
			string user = user_pw[0 .. idx];
			string password = user_pw[idx+1 .. $];

			if( pwcheck(user, password) ){
				req.username = user;
				// let the next stage handle the request
				return;
			}
		}
	}*/

  router.any("*", &handler.checkLogin);
}
