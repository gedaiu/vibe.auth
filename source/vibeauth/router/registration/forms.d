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

class RegistrationForms {

	private {
		IChallenge challenge;
		const RegistrationConfiguration configuration;
	}

	this(IChallenge challenge, const RegistrationConfiguration configuration) {
		this.challenge = challenge;
		this.configuration = configuration;
	}

	void registerForm(HTTPServerRequest req, HTTPServerResponse res) {
		auto const style = configuration.style;
		auto const challenge = challenge.getTemplate(configuration.paths.challange);
		auto const addUserPath = configuration.paths.addUser;
		auto const userData = const RequestUserData(req);

		res.render!("registerForm.dt", style, challenge, addUserPath, userData);
	}

	void confirmationForm(HTTPServerRequest req, HTTPServerResponse res) {
		res.statusCode = 200;
		auto const style = configuration.style;
		auto const activation = configuration.paths.activation;

		res.render!("registerConfirmation.dt", style, activation);
	}
}
