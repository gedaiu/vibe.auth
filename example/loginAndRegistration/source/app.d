import std.stdio;
import std.path;
import std.file;

import vibeauth.challenges.mathcaptcha;
import vibeauth.client;
import vibeauth.users;
import vibeauth.router.registration.routes;
import vibeauth.router.login;
import vibeauth.mail.sendmail;
import vibeauth.token;
import vibeauth.router.request;

import vibe.d;

const RegistrationConfiguration registerConfiguration;

UserMemmoryCollection collection;

void handler(HTTPServerRequest req, HTTPServerResponse res) {
	const auto style = registerConfiguration.style;

	User user = req.user(collection);

	res.render!("index.dt", style, user);
}

shared static this()
{
	auto settings = new HTTPServerSettings;
	settings.port = 8888;
	settings.options = HTTPServerOption.parseCookies | HTTPServerOption.parseFormBody | HTTPServerOption.parseQueryString | HTTPServerOption.parseJsonBody;

	auto router = new URLRouter();

	collection = new UserMemmoryCollection(["doStuff"]);

	auto configurationJson = readText("configuration.json").parseJsonString;
	configurationJson["email"]["confirmationText"] = readText("emails/registration.txt");
	configurationJson["email"]["confirmationHtml"] = readText("emails/registration.html");

	registerConfiguration = configurationJson.deserializeJson!RegistrationConfiguration;

	MathCaptchaSettings captchaSettings;
	captchaSettings.fontName = buildNormalizedPath(getcwd, "fonts/warpstorm/WarpStorm.otf");

	auto mailQueue = new SendMailQueue(registerConfiguration.email);

	auto registrationRoutes = new RegistrationRoutes(collection,
		new MathCaptcha(captchaSettings),
		mailQueue,
		registerConfiguration);

	LoginConfiguration loginConfiguration;
	loginConfiguration.templates.login = "views/loginTemplate.html";
	loginConfiguration.templates.reset = "views/resetTemplate.html";
	loginConfiguration.style = registerConfiguration.style;

	auto loginRoutes = new LoginRoutes(collection, mailQueue, loginConfiguration);

	router
		.get("*", serveStaticFiles("./public/"))
		.any("*", &registrationRoutes.handler)
		.any("*", &loginRoutes.handler)
		.any("*", &handler);

	listenHTTP(settings, router);
}
