module vibeauth.router.registration;

import std.stdio;
import std.datetime;
import std.algorithm;

import vibe.http.router;
import vibe.data.json;
import vibe.inet.url;

import vibeauth.users;
import vibeauth.challenges.base;
import vibeauth.mail.base;
import vibeauth.router.accesscontrol;

struct RegistrationConfiguration {
	string registerPath = "/register";
	string addUserPath = "/register/user";
	string activationPath = "/register/activation";
	string challangePath = "/register/challenge";

	string style = "";
}

class RegistrationRoutes {

	private {
		UserCollection collection;
		IChallenge challenge;
		IMailQueue mailQueue;
		const RegistrationConfiguration configuration;
	}

	this(UserCollection collection, IChallenge challenge, IMailQueue mailQueue, const RegistrationConfiguration configuration = RegistrationConfiguration()) {
		this.collection = collection;
		this.challenge = challenge;
		this.mailQueue = mailQueue;
		this.configuration = configuration;
	}

	void registration(HTTPServerRequest req, HTTPServerResponse res) {
		try {
			setAccessControl(res);
			if(req.method == HTTPMethod.OPTIONS) {
				return;
			}

			if(req.method == HTTPMethod.GET && req.path == configuration.registerPath) {
				registerForm(req, res);
			}

			if(req.method == HTTPMethod.POST && req.path == configuration.addUserPath) {
				addUser(req, res);
			}

			if(req.method == HTTPMethod.GET && req.path == configuration.activationPath) {
				activation(req, res);
			}

			if(req.method == HTTPMethod.GET && req.path == configuration.challangePath) {
				challenge.generate(req, res);
			}

		} catch(Exception e) {
			version(unittest) {} else debug stderr.writeln(e);

			if(!res.headerWritten) {
				res.writeJsonBody([ "error": e.msg ], 500);
			}
		}
	}

	private void registerForm(HTTPServerRequest req, HTTPServerResponse res) {
		auto const style = configuration.style;
		auto const challenge = this.challenge.getTemplate(configuration.challangePath);

		res.render!("registerForm.dt", style, challenge);
	}

	private void activation(HTTPServerRequest req, HTTPServerResponse res) {
		if("token" !in req.query || "email" !in req.query) {
			res.statusCode = 400;
			res.writeJsonBody(["error": ["message": "invalid request"]]);

			return;
		}

		auto token = req.query["token"];
		auto email = req.query["email"];

		if(!collection.contains(email)) {
			res.statusCode = 400;
			res.writeJsonBody(["error": ["message": "invalid request"]]);

			return;
		}

		auto user = collection[email];

		if(!user.isValidToken(token)) {
			res.statusCode = 400;
			res.writeJsonBody(["error": ["message": "invalid request"]]);

			return;
		}

		user.isActive = true;
		user.getTokensByType("activation").each!(a => user.revoke(a.name));

		res.statusCode = 200;
		res.writeVoidBody;
	}

	private void addUser(HTTPServerRequest req, HTTPServerResponse res) {
		UserData data;

		if("name" !in req.json) {
			res.statusCode = 400;
			res.writeJsonBody(["error": ["message": "`name` is missing"]]);
			return;
		}

		if("username" !in req.json) {
			res.statusCode = 400;
			res.writeJsonBody(["error": ["message": "`username` is missing"]]);
			return;
		}

		if("email" !in req.json) {
			res.statusCode = 400;
			res.writeJsonBody(["error": ["message": "`email` is missing"]]);
			return;
		}

		if("password" !in req.json) {
			res.statusCode = 400;
			res.writeJsonBody(["error": ["message": "`password` is missing"]]);
			return;
		}

		if("response" !in req.json) {
			res.statusCode = 400;
			res.writeJsonBody(["error": ["message": "`response` is missing"]]);
			return;
		}

		if(!challenge.validate(req, res, req.json["response"].to!string)) {
			res.statusCode = 400;
			res.writeJsonBody(["error": ["message": "Invalid `response` challenge"]]);
			return;
		}

		data.name = req.json["name"].to!string;
		data.username = req.json["username"].to!string;
		data.email = req.json["email"].to!string;
		data.isActive = false;

		collection.createUser(data, req.json["password"].to!string);
		auto token = collection.createToken(data.email, Clock.currTime + 3600.seconds, [], "activation");
		mailQueue.addActivationMessage(data, token);

		res.statusCode = 200;
		res.writeVoidBody;
	}
}

version(unittest) {
	import std.array;
	import http.request;
	import http.json;
	import bdd.base;
	import vibeauth.token;

	UserMemmoryCollection collection;
	User user;
	RegistrationRoutes registration;
	TestMailQueue mailQueue;
	Token activationToken;

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
		string generate(HTTPServerRequest, HTTPServerResponse) {
			return "123";
		}

		bool validate(HTTPServerRequest, HTTPServerResponse, string response) {
			return response == "123";
		}
	}

	auto testRouter() {
		auto router = new URLRouter();
		mailQueue = new TestMailQueue;

		collection = new UserMemmoryCollection(["doStuff"]);
		user = new User("user@gmail.com", "password");
		user.name = "John Doe";
		user.username = "test";
		user.id = 1;

		collection.add(user);
		activationToken = collection.createToken(user.email, Clock.currTime + 3600.seconds, [], "activation");

		registration = new RegistrationRoutes(collection, new TestChallenge, mailQueue);

		router.any("*", &registration.registration);
		return router;
	}
}

@("POST valid data should create the user")
unittest {
	auto router = testRouter;

	auto data = `{
		"name": "test",
		"username": "test_user",
		"email": "test@test.com",
		"password": "testPassword",
		"response": "123"
	}`.parseJsonString;

	router
		.request
		.post("/register/user")
		.send(data)
		.expectStatusCode(200)
		.end((Response response) => {
			collection.contains("test@test.com").should.be.equal(true);

			collection["test@test.com"].name.should.equal("test");
			collection["test@test.com"].username.should.equal("test_user");
			collection["test@test.com"].email.should.equal("test@test.com");
			collection["test@test.com"].isActive.should.equal(false);
			collection["test@test.com"].isValidPassword("testPassword").should.equal(true);

			auto tokens = collection["test@test.com"].getTokensByType("activation").array;

			tokens.length.should.equal(1);
			collection["test@test.com"].isValidToken(tokens[0].name).should.equal(true);
		});
}

@("POST valid data should send a validation email")
unittest {
	auto router = testRouter;

	auto data = `{
		"name": "test",
		"username": "test_user",
		"email": "test@test.com",
		"password": "testPassword",
		"response": "123"
	}`.parseJsonString;

	router
		.request
		.post("/register/user")
		.send(data)
		.expectStatusCode(200)
		.end((Response response) => {
			string activationLink = "http://localhost/register/activation?email=test@test.com&token="
				~ collection["test@test.com"].getTokensByType("activation").front.name;

			mailQueue.messages.length.should.equal(1);
			mailQueue.messages[0].textMessage.should.contain(activationLink);
			mailQueue.messages[0].htmlMessage.should.contain(`<a href="` ~ activationLink ~ `">`);
		});
}

@("GET with valid token should validate the user")
unittest {
	auto router = testRouter;

	collection["user@gmail.com"].isActive.should.equal(false);

	router
		.request
		.get("/register/activation?email=user@gmail.com&token=" ~ activationToken.name)
		.expectStatusCode(200)
		.end((Response response) => {
			collection["user@gmail.com"].isValidToken(activationToken.name).should.equal(false);
			collection["user@gmail.com"].isActive.should.equal(true);
		});
}

@("GET with invalid token should not validate the user")
unittest {
	auto router = testRouter;

	collection["user@gmail.com"].isActive.should.equal(false);

	router
		.request
		.get("/register/activation?email=user@gmail.com&token=other")
		.expectStatusCode(400)
		.end((Response response) => {
			collection["user@gmail.com"].isValidToken(activationToken.name).should.equal(true);
			collection["user@gmail.com"].isActive.should.equal(false);
		});
}

@("POST with missing data should return an error")
unittest {
	auto router = testRouter;

	auto data = `{
		"username": "test_user",
		"email": "test@test.com",
		"password": "testPassword",
		"response": "123"
	}`.parseJsonString;

	router
		.request
		.post("/register/user")
		.send(data)
		.expectStatusCode(400)
		.end((Response response) => {
			response.bodyJson.keys.should.contain("error");
			response.bodyJson["error"].keys.should.contain("message");
		});

	data = `{
		"name": "test",
		"email": "test@test.com",
		"password": "testPassword",
		"response": "123"
	}`.parseJsonString;

	router
		.request
		.post("/register/user")
		.send(data)
		.expectStatusCode(400)
		.end((Response response) => {
			response.bodyJson.keys.should.contain("error");
			response.bodyJson["error"].keys.should.contain("message");
		});

	data = `{
		"name": "test",
		"username": "test_user",
		"password": "testPassword",
		"response": "123"
	}`.parseJsonString;

	router
		.request
		.post("/register/user")
		.send(data)
		.expectStatusCode(400)
		.end((Response response) => {
			response.bodyJson.keys.should.contain("error");
			response.bodyJson["error"].keys.should.contain("message");
		});

	data = `{
		"name": "test",
		"username": "test_user",
		"email": "test@test.com",
		"response": "123"
	}`.parseJsonString;

	router
		.request
		.post("/register/user")
		.send(data)
		.expectStatusCode(400)
		.end((Response response) => {
			response.bodyJson.keys.should.contain("error");
			response.bodyJson["error"].keys.should.contain("message");
		});

	data = `{
		"name": "test",
		"username": "test_user",
		"email": "test@test.com",
		"password": "testPassword"
	}`.parseJsonString;

	router
		.request
		.post("/register/user")
		.send(data)
		.expectStatusCode(400)
		.end((Response response) => {
			response.bodyJson.keys.should.contain("error");
			response.bodyJson["error"].keys.should.contain("message");
		});
}

@("POST with wrong response should return an error")
unittest {
	auto router = testRouter;

	auto data = `{
		"name": "test",
		"username": "test_user",
		"email": "test@test.com",
		"password": "testPassword",
		"response": "abc"
	}`.parseJsonString;

	router
		.request
		.post("/register/user")
		.send(data)
		.expectStatusCode(400)
		.end((Response response) => {
			response.bodyJson.keys.should.contain("error");
			response.bodyJson["error"].keys.should.contain("message");
		});
}
