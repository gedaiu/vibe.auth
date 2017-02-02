module vibeauth.router.registration;

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

struct RegistrationConfigurationPaths {
	string register = "/register";
	string addUser = "/register/user";
	string activation = "/register/activation";
	string challange = "/register/challenge";
	string confirmation = "/register/confirmation";
}

struct RegistrationConfiguration {
	RegistrationConfigurationPaths paths;
	RegistrationConfigurationEmail email;

	string serviceName = "Unknown app";
	string location = "http://localhost";
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

			if(req.method == HTTPMethod.GET && req.path == configuration.paths.register) {
				registerForm(req, res);
			}

			if(req.method == HTTPMethod.POST && req.path == configuration.paths.addUser) {
				if(req.contentType.toLower.indexOf("json") != -1) {
					addJsonUser(req, res);
				} else {
					addHtmlUser(req, res);
				}
			}

			if(req.method == HTTPMethod.GET && req.path == configuration.paths.activation) {
				activation(req, res);
			}

			if(req.method == HTTPMethod.GET && req.path == configuration.paths.challange) {
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
		auto const challenge = this.challenge.getTemplate(configuration.paths.challange);
		auto const addUserPath = configuration.paths.addUser;
		auto const values = getAddUserData(req);

		auto const name = "name" in values ? values["name"] : "";
		auto const username = "username" in values ? values["username"] : "";
		auto const email = "email" in values ? values["email"] : "";
		auto const error = "error" in req.query ? req.query["error"] : "";

		res.render!("registerForm.dt", style, challenge, addUserPath,
			name, username, email, error);
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

	string[string] getAddUserData(HTTPServerRequest req) {
		string[string] data;

		if(req.json.type == Json.Type.object) {
			foreach(string key, value; req.json) {
				data[key] = value.to!string;
			}
		}

		foreach(string key, value; req.query) {
			value = value.strip;

			if(value.length > 0) {
				data[key] = value;
			}
		}

		foreach(string key, value; req.form) {
			value = value.strip;

			if(value.length > 0) {
				data[key] = value;
			}
		}

		return data;
	}

	private string queryUserData(string[string] values, string error = "") {
		string query = "?error=" ~ encodeComponent(error);

		if("name" in values) {
			query ~= "&name=" ~ encodeComponent(values["name"]);
		}

		if("username" in values) {
			query ~= "&username=" ~ encodeComponent(values["username"]);
		}

		if("email" in values) {
			query ~= "&email=" ~ encodeComponent(values["email"]);
		}
		return query;
	}

	private void addHtmlUser(HTTPServerRequest req, HTTPServerResponse res) {
		auto values = getAddUserData(req);

		if("name" !in values) {
			res.redirect(configuration.paths.register ~ queryUserData(values, "`name` is missing"));
			return;
		}

		if("username" !in values) {
			res.redirect(configuration.paths.register ~ queryUserData(values, "`username` is missing"));
			return;
		}

		if("email" !in values) {
			res.redirect(configuration.paths.register ~ queryUserData(values, "`email` is missing"));
			return;
		}

		if("password" !in values) {
			res.redirect(configuration.paths.register ~ queryUserData(values, "`password` is missing"));
			return;
		}

		if("response" !in values) {
			res.redirect(configuration.paths.register ~ queryUserData(values, "`response` is missing"));
			return;
		}

		if(!challenge.validate(req, res, values["response"])) {
			res.redirect(configuration.paths.register ~ queryUserData(values, "Invalid challenge `response`"));
			return;
		}

		UserData data;
		data.name = values["name"];
		data.username = values["username"];
		data.email = values["email"];
		data.isActive = false;

		collection.createUser(data, values["password"]);
		auto token = collection.createToken(data.email, Clock.currTime + 3600.seconds, [], "activation");
		mailQueue.addActivationMessage(data, token);

		res.statusCode = 200;

		auto const style = configuration.style;
		auto const confirmation = configuration.paths.confirmation;

		res.render!("registerSuccess.dt", style, confirmation);
	}

	private void addJsonUser(HTTPServerRequest req, HTTPServerResponse res) {
		auto values = getAddUserData(req);

		if("name" !in values) {
			res.statusCode = 400;
			res.writeJsonBody(["error": ["message": "`name` is missing"]]);
			return;
		}

		if("username" !in values) {
			res.statusCode = 400;
			res.writeJsonBody(["error": ["message": "`username` is missing"]]);
			return;
		}

		if("email" !in values) {
			res.statusCode = 400;
			res.writeJsonBody(["error": ["message": "`email` is missing"]]);
			return;
		}

		if("password" !in values) {
			res.statusCode = 400;
			res.writeJsonBody(["error": ["message": "`password` is missing"]]);
			return;
		}

		if("response" !in values) {
			res.statusCode = 400;
			res.writeJsonBody(["error": ["message": "`response` is missing"]]);
			return;
		}

		if(!challenge.validate(req, res, values["response"])) {
			res.statusCode = 400;
			res.writeJsonBody(["error": ["message": "Invalid challenge `response`"]]);
			return;
		}

		UserData data;
		data.name = values["name"];
		data.username = values["username"];
		data.email = values["email"];
		data.isActive = false;

		collection.createUser(data, values["password"]);
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

	class TestMailQueue : MailQueue
	{
		Message[] messages;

		this() {
			super(RegistrationConfigurationEmail());
		}

		override
		void addMessage(Message message) {
			messages ~= message;
		}
	}

	class TestChallenge : IChallenge {
		string generate(HTTPServerRequest, HTTPServerResponse) {
			return "123";
		}

		bool validate(HTTPServerRequest, HTTPServerResponse, string response) {
			return response == "123";
		}

		string getTemplate(string challangeLocation) {
			return "";
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
		.header("Content-Type", "application/json")
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
		.header("Content-Type", "application/json")
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
		.header("Content-Type", "application/json")
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
		.header("Content-Type", "application/json")
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
		.header("Content-Type", "application/json")
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
		.header("Content-Type", "application/json")
		.expectStatusCode(400)
		.end((Response response) => {
			response.bodyJson.keys.should.contain("error");
			response.bodyJson["error"].keys.should.contain("message");
		});
}
