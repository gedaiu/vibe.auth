import std.stdio;
import std.path;
import std.file;

import vibeauth.challenges.mathcaptcha;
import vibeauth.client;
import vibeauth.users;
import vibeauth.router.registration;
import vibeauth.mail.base;
import vibeauth.token;

import vibe.d;

class TestMailQueue : IMailQueue
{
	Message[] messages;

	void addMessage(Message message) {
		messages ~= message;
	}

	void addActivationMessage(UserData data, Token token) {
		Message message;

		string link = "http://localhost/register/activation?email=" ~
			data.email ~
			"&token=" ~ token.name;

		message.textMessage = link;
		message.htmlMessage = `<a href="` ~ link ~ `">`;

		addMessage(message);
	}
}

shared static this()
{
	auto settings = new HTTPServerSettings;
	settings.port = 8888;
	settings.options = HTTPServerOption.parseCookies | HTTPServerOption.parseFormBody | HTTPServerOption.parseQueryString | HTTPServerOption.parseJsonBody;

	auto router = new URLRouter();

	auto collection = new UserMemmoryCollection(["doStuff"]);

	RegistrationConfiguration configuration;
	configuration.style = "https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css";

	MathCaptchaSettings captchaSettings;
	captchaSettings.fontName = buildNormalizedPath(getcwd, "fonts/warpstorm/WarpStorm.otf");

	auto registration = new RegistrationRoutes(collection, new MathCaptcha(captchaSettings), new TestMailQueue, configuration);
	router.any("*", &registration.registration);

	listenHTTP(settings, router);
}
