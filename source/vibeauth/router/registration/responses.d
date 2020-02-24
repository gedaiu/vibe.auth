module vibeauth.router.registration.responses;

import std.stdio;
import std.datetime;
import std.string;
import std.uri;
import std.file;

import vibe.http.router;
import vibe.data.json;


import vibeauth.configuration;
import vibeauth.challenges.base;
import vibeauth.mail.base;
import vibeauth.router.accesscontrol;
import vibeauth.router.registration.routes;
import vibeauth.router.request;
import vibeauth.mvc.templatedata;
import vibeauth.mvc.view;

class RegistrationResponses {

  private {
    IChallenge challenge;
    const {
      ServiceConfiguration configuration;
    }
  }

  this(IChallenge challenge, const ServiceConfiguration configuration) {
    this.challenge = challenge;
    this.configuration = configuration;
  }

  void registerForm(HTTPServerRequest req, HTTPServerResponse res) {
    scope view = new RegisterView(configuration);

    Json variables = Json.emptyObject;
    variables["challenge"] = challenge.getTemplate(configuration.paths.registration.challange);
    variables["userData"] = (const RequestUserData(req)).toJson;

    if(variables["userData"]["error"].type == Json.Type.string && variables["userData"]["error"] != "") {
      view.data.addError(variables["userData"]["error"].to!string);
    }

    view.data.add(variables);

    res.writeBody(view.render, "text/html");
  }

  void confirmationForm(HTTPServerRequest, HTTPServerResponse res) {
    scope view = new ConfirmationView(configuration);

    res.statusCode = 200;
    res.writeBody(view.render, "text/html");
  }

  void success(HTTPServerRequest, HTTPServerResponse res) {
    scope view = new SuccessView(configuration);

    res.statusCode = 200;
    res.writeBody(view.render, "text/html");
  }
}

alias RegisterView = BasicView!(
  "templates.registration.formTemplate",
  "templates.registration.form"
);

alias ConfirmationView = BasicView!(
  "templates.registration.confirmationTemplate",
  "templates.registration.confirmation"
);

alias SuccessView = BasicView!(
  "templates.registration.successTemplate",
  "templates.registration.success"
);
