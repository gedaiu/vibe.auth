module vibeauth.authenticators.OAuth2;

import vibe.inet.url;
import vibe.http.router;
import vibe.http.server;
import vibe.data.json;

import vibeauth.authenticators.oauth.AuthData;
import vibeauth.authenticators.BaseAuth;
import vibeauth.router.responses;
import vibeauth.router.accesscontrol;
import vibeauth.collections.usercollection;
import vibeauth.data.user;

import std.datetime;
import std.stdio;
import std.string;
import std.conv;


/// OAuth2 configuration
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

/// OAuth2 autenticator
class OAuth2 : BaseAuth {
  protected {
    const OAuth2Configuration configuration;
  }

  ///
  this(UserCollection userCollection, const OAuth2Configuration configuration = OAuth2Configuration()) {
    super(userCollection);

    this.configuration = configuration;
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
    void mandatoryAuth(HTTPServerRequest req, HTTPServerResponse res) {
      super.mandatoryAuth(req, res);
    }

    void permisiveAuth(HTTPServerRequest req, HTTPServerResponse res) {
      super.permisiveAuth(req, res);
    }

    /// Auth handler that will fail if a successfull auth was not performed.
    /// This handler is usefull for routes that want to hide information to the
    /// public.
    AuthResult mandatoryAuth(HTTPServerRequest req) {
      auto result = AuthResult.success;

      if(req.method == HTTPMethod.OPTIONS) {
        return AuthResult.success;
      }

      result = isValidBearer(req);

      if(req.path == configuration.style) {
        result = AuthResult.success;
      }

      return result;
    }

    /// Auth handler that fails only if the auth fields are present and are not valid.
    /// This handler is usefull when a route should return different data when the user is
    /// logged in
    AuthResult permisiveAuth(HTTPServerRequest req) {
      if("Authorization" !in req.headers) {
        return AuthResult.success;
      }

      return mandatoryAuth(req);
    }

    void respondUnauthorized(HTTPServerResponse res) {
      vibeauth.router.responses.respondUnauthorized(res);
    }

    void respondInvalidToken(HTTPServerResponse res) {
      vibeauth.router.responses.respondUnauthorized(res, "Invalid token.", 400);
    }
  }

  private {
    /// Validate the authorization token
    AuthResult isValidBearer(HTTPServerRequest req) {
      auto pauth = "Authorization" in req.headers;

      if(pauth && (*pauth).startsWith("Bearer ")) {
        auto token = (*pauth)[7 .. $];

        try {
          auto const user = collection.byToken(token);
          req.username = user.id;
          req.context["email"] = user.email;
        } catch(Exception e) {
          return AuthResult.invalidToken;
        }

        return AuthResult.success;
      }

      return AuthResult.unauthorized;
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

      /*
      if(clientId !in clientCollection) {
        showError(res, "Invalid `client_id` parameter");
        return;
      }

      string appTitle = clientCollection[clientId].name;

      */
      /// res.render!("loginForm.dt", appTitle, redirectUri, state, style);
    }


    /// Show an HTML error
    void showError(HTTPServerResponse res, const string error) {
      auto const style = configuration.style;
      res.statusCode = 400;
      //res.render!("error.dt", error, style);
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

      //res.render!("redirect.dt", redirectUri);
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

      res.setCookie("ember_simple_auth-session", null);
      res.statusCode = 200;
      res.writeBody("");
    }
  }
}
