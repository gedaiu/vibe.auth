module vibeauth.router.login.responses;

import std.stdio;
import std.datetime;
import std.string;
import std.uri;
import std.file;

import vibe.http.router;
import vibe.data.json;

import vibeauth.users;
import vibeauth.mail.base;
import vibeauth.router.login.routes;
import vibeauth.router.request;
import vibeauth.templatehelper;

class LoginResponses {

  private {
    immutable {
      string loginFormTemplate;
      string resetFormPage;
    }

    const LoginConfiguration configuration;
  }

  this(const LoginConfiguration configuration = LoginConfiguration()) {
    this.loginFormTemplate = prepareLoginTemplate;
    this.resetFormPage = prepareResetFormPage;
    this.configuration = configuration;
  }

  private {
    string prepareResetFormPage() {
      string destination = import("login/resetTemplate.html");
      const form = import("login/reset.html");

      if(configuration.templates.reset != "") {
        destination = readText(configuration.templates.reset);
      }

      return destination.replace("#{body}", form).replaceVariables(configuration.serializeToJson);
    }

    string prepareLoginTemplate() {
      string destination = import("login/template.html");
      const form = import("login/form.html");

      if(configuration.templates.login  != "") {
        destination = readText(configuration.templates.login);
      }

      return destination.replace("#{body}", form).replaceVariables(configuration.serializeToJson);
    }
  }

  void resetForm(HTTPServerRequest, HTTPServerResponse res) {
    res.writeBody(resetFormPage, 200, "text/html; charset=UTF-8" );
  }

  void loginForm(HTTPServerRequest req, HTTPServerResponse res) {
    auto requestData = const RequestUserData(req);
		Json data = Json.emptyObject;

		data["email"] = requestData.email;
		data["error"] = requestData.error == "" ? "" :
			`<div class="alert alert-danger" role="alert">` ~ requestData.error ~ `</div>`;
		data["message"] = requestData.message == "" ? "" :
			`<div class="alert alert-info" role="alert">` ~ requestData.message ~ `</div>`;

		string loginFormPage = loginFormTemplate.replaceVariables(data);

		res.writeBody(loginFormPage, 200, "text/html; charset=UTF-8" );
  }
}
