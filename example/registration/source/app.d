import std.stdio;
import std.path;
import std.file;

import vibeauth.challenges.mathcaptcha;
import vibeauth.client;
import vibeauth.users;
import vibeauth.router.registration.routes;
import vibeauth.mail.sendmail;
import vibeauth.token;
import vibeauth.configuration;
import vibeauth.mail.base;

import vibe.d;

shared static this()
{
	auto settings = new HTTPServerSettings;
	settings.port = 8888;

	auto router = new URLRouter();

	auto collection = new UserMemmoryCollection(["doStuff"]);

	auto configurationJson = readText("configuration.json").parseJsonString;

	configurationJson["email"]["confirmationText"] = readText("emails/registration.txt");
	configurationJson["email"]["confirmationHtml"] = readText("emails/registration.html");

	auto configuration = configurationJson.deserializeJson!RegistrationConfiguration;

	MathCaptchaSettings captchaSettings;
	captchaSettings.fontName = buildNormalizedPath(getcwd, "fonts/warpstorm/WarpStorm.otf");

	auto registration = new RegistrationRoutes(collection,
		new MathCaptcha(captchaSettings),
		new SendMailQueue(EmailConfiguration()),
		configuration);

	router.any("*", &registration.handler);

	listenHTTP(settings, router);
}
