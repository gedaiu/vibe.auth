module vibeauth.router.login.responses;

import std.stdio;
import std.datetime;
import std.string;
import std.uri;
import std.file;

import vibe.http.router;
import vibe.data.json;

import vibeauth.users;
import vibeauth.configuration;
import vibeauth.mail.base;
import vibeauth.router.login.routes;
import vibeauth.router.request;
import vibeauth.mvc.templatedata;
import vibeauth.mvc.view;

/// User
class LoginResponses {

  private {
    const {
      ServiceConfiguration configuration;
    }
  }

  this(const ServiceConfiguration configuration) {
    this.configuration = configuration;
  }

  void resetForm(HTTPServerRequest req, HTTPServerResponse res) {
    auto requestData = const RequestUserData(req);

    if(requestData.email == "" || requestData.token == "") {
      scope auto view = new ResetView(configuration);
      res.writeBody(view.render, 200, "text/html; charset=UTF-8" );
      return;
    }

    scope auto view = new ChangePasswordView(configuration);
    Json data = Json.emptyObject;

    data["email"] = requestData.email;
    data["token"] = requestData.token;

    if(requestData.error != "") {
      view.data.addError(requestData.error);
    }

    view.data.add(data);

    res.writeBody(view.render, 200, "text/html; charset=UTF-8" );
  }

  void loginForm(HTTPServerRequest req, HTTPServerResponse res) {
    auto view = new LoginView(configuration);
    auto requestData = const RequestUserData(req);
    Json data = Json.emptyObject;

    data["username"] = requestData.username;

    if(requestData.error != "") {
      view.data.addError(requestData.error);
    }

    if(requestData.message != "") {
      view.data.addMessage(requestData.message);
    }

    view.data.add(data);
    res.writeBody(view.render, 200, "text/html; charset=UTF-8" );
  }
}

alias LoginView = BasicView!(
  "templates.login.formTemplate",
  "templates.login.form"
);

alias ResetView = BasicView!(
  "templates.login.resetTemplate",
  "templates.login.reset"
);

alias ChangePasswordView = BasicView!(
  "templates.login.resetTemplate",
  "templates.login.resetPassword"
);