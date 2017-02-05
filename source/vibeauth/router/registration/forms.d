module vibeauth.router.registration.forms;

import std.stdio;
import std.datetime;
import std.algorithm;
import std.string;
import std.uri;

import vibe.http.router;
import vibe.data.json;
import vibe.inet.url;

import vibeauth.users;
import vibeauth.challenges.base;
import vibeauth.mail.base;
import vibeauth.router.accesscontrol;
import vibeauth.router.registration.routes;
import vibeauth.router.registration.request;
import vibeauth.challenges.base;
import vibeauth.templatehelper;

class RegistrationForms {

	private {
		IChallenge challenge;
		const RegistrationConfiguration configuration;


		immutable {
			string confirmationPage;
			string formTemplate;
		}
	}

	this(IChallenge challenge, const RegistrationConfiguration configuration) {
		this.challenge = challenge;
		this.configuration = configuration;

		this.formTemplate = prepareFormTemplate;
		this.confirmationPage = prepareConfirmationPage;
	}

	private string prepareFormTemplate() {
		const defaultDestination = import("register/formTemplate.html");
		const form = import("register/form.html");

		return defaultDestination.replace("#{body}", form).replaceVariables(configuration.serializeToJson);
	}

	private string prepareConfirmationPage() {
		const defaultDestination = import("register/confirmationTemplate.html");
		const message = import("register/confirmation.html");

		return defaultDestination.replace("#{body}", message).replaceVariables(configuration.serializeToJson);
	}

	void registerForm(HTTPServerRequest req, HTTPServerResponse res) {
		Json variables = Json.emptyObject;
		variables["challenge"] = challenge.getTemplate(configuration.paths.challange);
		variables["userData"] = (const RequestUserData(req)).toJson;

		if(variables["userData"]["error"].type == Json.Type.string && variables["userData"]["error"] != "") {
			variables["userData"]["error"] = `<div class="alert alert-danger" role="alert">` ~
				variables["userData"]["error"].to!string ~
				`</div>`;
		}

		string formPage = formTemplate.replaceVariables(variables);

		res.writeBody(formPage, "text/html");
	}

	void confirmationForm(HTTPServerRequest req, HTTPServerResponse res) {
		res.statusCode = 200;
		res.writeBody(confirmationPage, "text/html");
	}
}
