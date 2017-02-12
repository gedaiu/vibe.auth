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
import vibeauth.templatehelper;

class LoginResponses {

  private {
    immutable {
      string loginFormTemplate;
      string resetFormPage;
      string resetPasswordTemplate;
    }

    const {
      LoginConfiguration configuration;
      ServiceConfiguration serviceConfiguration;
    }
  }

  this(const LoginConfiguration configuration, const ServiceConfiguration serviceConfiguration) {
    this.configuration = configuration;
    this.serviceConfiguration = serviceConfiguration;
    this.loginFormTemplate = prepareLoginTemplate;
    this.resetFormPage = prepareResetFormPage;
    this.resetPasswordTemplate = prepareResetPasswordTemplate;
  }

  private {
    string prepareResetPasswordTemplate() {
      string destination = import("login/resetTemplate.html");
      const form = import("login/resetPasswordForm.html");

      if(configuration.templates.reset != "") {
        destination = readText(configuration.templates.reset);
      }

      return destination.replace("#{body}", form)
        .replaceVariables(serviceConfiguration.serializeToJson)
        .replaceVariables(configuration.serializeToJson);
    }

    string prepareResetFormPage() {
      string destination = import("login/resetTemplate.html");
      const form = import("login/reset.html");

      if(configuration.templates.reset != "") {
        destination = readText(configuration.templates.reset);
      }

      return destination.replace("#{body}", form)
        .replaceVariables(serviceConfiguration.serializeToJson)
        .replaceVariables(configuration.serializeToJson);
    }

    string prepareLoginTemplate() {
      string destination = import("login/template.html");
      const form = import("login/form.html");

      if(configuration.templates.login != "") {
        destination = readText(configuration.templates.login);
      }

      return destination.replace("#{body}", form)
        .replaceVariables(configuration.serializeToJson)
        .replaceVariables(serviceConfiguration.serializeToJson);
    }
  }

  void resetForm(HTTPServerRequest req, HTTPServerResponse res) {
    auto requestData = const RequestUserData(req);

    if(requestData.email == "" || requestData.token == "") {
      res.writeBody(resetFormPage, 200, "text/html; charset=UTF-8" );
      return;
    }

    Json data = Json.emptyObject;

		data["email"] = requestData.email;
		data["token"] = requestData.token;
		data["error"] = requestData.error == "" ? "" :
			`<div class="alert alert-danger" role="alert">` ~ requestData.error ~ `</div>`;

		string resetPasswordPage = resetPasswordTemplate.replaceVariables(data);

		res.writeBody(resetPasswordPage, 200, "text/html; charset=UTF-8" );
  }

  void loginForm(HTTPServerRequest req, HTTPServerResponse res) {
    auto requestData = const RequestUserData(req);
		Json data = Json.emptyObject;

		data["username"] = requestData.username;
		data["error"] = requestData.error == "" ? "" :
			`<div class="alert alert-danger" role="alert">` ~ requestData.error ~ `</div>`;
		data["message"] = requestData.message == "" ? "" :
			`<div class="alert alert-info" role="alert">` ~ requestData.message ~ `</div>`;

		string loginFormPage = loginFormTemplate.replaceVariables(data);

		res.writeBody(loginFormPage, 200, "text/html; charset=UTF-8" );
  }
}
