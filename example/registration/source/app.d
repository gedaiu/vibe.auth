import std.stdio;
import std.path;
import std.file;

import vibeauth.challenges.mathcaptcha;
import vibeauth.client;
import vibeauth.users;
import vibeauth.router.registration;
import vibeauth.mail.sendmail;
import vibeauth.token;

import vibe.d;

shared static this()
{
	auto settings = new HTTPServerSettings;
	settings.port = 8888;
	settings.options = HTTPServerOption.parseCookies | HTTPServerOption.parseFormBody | HTTPServerOption.parseQueryString | HTTPServerOption.parseJsonBody;

	auto router = new URLRouter();

	auto collection = new UserMemmoryCollection(["doStuff"]);

	RegistrationConfiguration configuration;
	configuration.serviceName = "Demo App";
	configuration.location = "http://localhost:8888";
	configuration.style = "https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css";

	configuration.email.confirmationText = readText("emails/registration.txt");
	configuration.email.confirmationHtml = readText("emails/registration.html");

	configuration.email.writeln;

	MathCaptchaSettings captchaSettings;
	captchaSettings.fontName = buildNormalizedPath(getcwd, "fonts/warpstorm/WarpStorm.otf");

	auto registration = new RegistrationRoutes(collection, new MathCaptcha(captchaSettings), new SendMailQueue(configuration.email), configuration);
	router.any("*", &registration.registration);

	listenHTTP(settings, router);
}
