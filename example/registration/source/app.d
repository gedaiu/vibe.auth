import std.stdio;
import std.conv;
import std.string;

import vibeauth.challenges.base;
import vibeauth.client;
import vibeauth.users;
import vibeauth.router.registration;
import vibeauth.mail.base;
import vibeauth.token;
import vibeauth.challenges.imagegenerator;

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

class TestChallenge : IChallenge {
	string generate(HTTPServerRequest, HTTPServerResponse res) {
		auto generator = ImageGenerator(350, 100);
		generator.setText("14-4=");
		generator.flush(res);

		return "123";
	}

	bool validate(HTTPServerRequest, HTTPServerResponse, string response) {
		return response == "123";
	}

	string getTemplate(string challangeLocation) {
		auto output = new MemoryOutputStream();
		output.compileDietFile!("challanges/math.dt", challangeLocation);
		return output.data.assumeUTF;
	}
}

shared static this()
{
	auto settings = new HTTPServerSettings;
	settings.port = 8888;
	settings.options = HTTPServerOption.parseFormBody | HTTPServerOption.parseQueryString | HTTPServerOption.parseJsonBody;

	auto router = new URLRouter();

	auto collection = new UserMemmoryCollection(["doStuff"]);

	RegistrationConfiguration configuration;
	configuration.style = "https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css";

	auto registration = new RegistrationRoutes(collection, new TestChallenge, new TestMailQueue, configuration);
	router.any("*", &registration.registration);

	listenHTTP(settings, router);
}
