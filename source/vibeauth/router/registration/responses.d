module vibeauth.router.registration.responses;

import std.stdio;
import std.datetime;
import std.string;
import std.uri;
import std.file;

import vibe.http.router;
import vibe.data.json;

import vibeauth.users;
import vibeauth.configuration;
import vibeauth.challenges.base;
import vibeauth.mail.base;
import vibeauth.router.accesscontrol;
import vibeauth.router.registration.routes;
import vibeauth.router.request;
import vibeauth.templatehelper;

class RegistrationResponses {

	private {
		IChallenge challenge;
		const {
			RegistrationConfiguration configuration;
			ServiceConfiguration serviceConfiguration;
		}

		immutable {
			string confirmationPage;
			string formTemplate;
			string successPage;
		}
	}

	this(IChallenge challenge, const RegistrationConfiguration configuration ,
			const ServiceConfiguration serviceConfiguration) {
		this.challenge = challenge;
		this.configuration = configuration;
		this.serviceConfiguration = serviceConfiguration;

		this.formTemplate = prepareFormTemplate;
		this.confirmationPage = prepareConfirmationPage;
		this.successPage = prepareSuccessPage;
	}

	private {
		string prepareSuccessPage() {
			string destination = import("register/successTemplate.html");
			const message = import("register/success.html");

			if(configuration.templates.success != "") {
				destination = readText(configuration.templates.success);
			}

			return destination
								.replace("#{body}", message)
								.replaceVariables(configuration.serializeToJson)
								.replaceVariables(serviceConfiguration.serializeToJson);
		}

		string prepareFormTemplate() {
			string destination = import("register/formTemplate.html");
			const form = import("register/form.html");

			if(configuration.templates.form != "") {
				destination = readText(configuration.templates.form);
			}

			return destination.replace("#{body}", form).replaceVariables(configuration.serializeToJson);
		}

		string prepareConfirmationPage() {
			string destination = import("register/confirmationTemplate.html");
			const message = import("register/confirmation.html");

			if(configuration.templates.confirmation != "") {
				destination = readText(configuration.templates.confirmation);
			}

			return destination
							.replace("#{body}", message)
							.replaceVariables(configuration.serializeToJson)
							.replaceVariables(serviceConfiguration.serializeToJson);
		}
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

		string formPage = formTemplate
			.replaceVariables(variables)
			.replaceVariables(serviceConfiguration.serializeToJson);

		res.writeBody(formPage, "text/html");
	}

	void confirmationForm(HTTPServerRequest, HTTPServerResponse res) {
		res.statusCode = 200;
		res.writeBody(confirmationPage, "text/html");
	}

	void success(HTTPServerRequest, HTTPServerResponse res) {
		res.statusCode = 200;
		res.writeBody(successPage, "text/html");
	}
}
