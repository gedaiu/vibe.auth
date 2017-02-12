import std.stdio;
import std.path;
import std.file;

import vibeauth.challenges.mathcaptcha;
import vibeauth.client;
import vibeauth.users;
import vibeauth.configuration;
import vibeauth.router.registration.routes;
import vibeauth.router.login.routes;
import vibeauth.mail.sendmail;
import vibeauth.token;
import vibeauth.router.request;
import vibeauth.mail.base;

import vibe.d;

const {
	RegistrationConfiguration registerConfiguration;
	LoginConfiguration loginConfiguration;
	EmailConfiguration emailConfiguration;
	ServiceConfiguration serviceConfiguration;
}

UserMemmoryCollection collection;

void handler(HTTPServerRequest req, HTTPServerResponse res) {
	const auto style = serviceConfiguration.style;

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
	configurationJson["email"]["activation"]["text"] = readText("emails/activation.txt");
	configurationJson["email"]["activation"]["html"] = readText("emails/activation.html");

	configurationJson["email"]["resetPassword"]["text"] = readText("emails/resetPassword.txt");
	configurationJson["email"]["resetPassword"]["html"] = readText("emails/resetPassword.html");

	serviceConfiguration = configurationJson["service"].deserializeJson!ServiceConfiguration;
	emailConfiguration = configurationJson["email"].deserializeJson!EmailConfiguration;
	registerConfiguration = configurationJson["registration"].deserializeJson!RegistrationConfiguration;
	loginConfiguration = configurationJson["login"].deserializeJson!LoginConfiguration;

	MathCaptchaSettings captchaSettings;
	captchaSettings.fontName = buildNormalizedPath(getcwd, "fonts/warpstorm/WarpStorm.otf");

	auto mailQueue = new SendMailQueue(emailConfiguration);

	auto registrationRoutes = new RegistrationRoutes(collection,
		new MathCaptcha(captchaSettings),
		mailQueue,
		registerConfiguration,
		serviceConfiguration);


	auto loginRoutes = new LoginRoutes(collection, mailQueue, loginConfiguration, serviceConfiguration);

	router
		.get("*", serveStaticFiles("./public/"))
		.any("*", &registrationRoutes.handler)
		.any("*", &loginRoutes.handler)
		.any("*", &handler);

	listenHTTP(settings, router);
}
