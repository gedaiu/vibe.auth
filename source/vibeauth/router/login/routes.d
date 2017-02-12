module vibeauth.router.login.routes;

import vibe.http.router;
import vibe.data.json;
import vibe.inet.url;

import std.algorithm, std.base64, std.string, std.stdio, std.conv, std.array;
import std.datetime, std.random, std.uri, std.file;

import vibe.core.core;

import vibeauth.users;
import vibeauth.client;
import vibeauth.collection;
import vibeauth.templatehelper;
import vibeauth.configuration;
import vibeauth.router.accesscontrol;
import vibeauth.router.baseAuthRouter;
import vibeauth.router.login.responses;
import vibeauth.router.request;
import vibeauth.mail.base;

class LoginRoutes {

	private {
		UserCollection userCollection;
		LoginConfiguration configuration;
		ServiceConfiguration serviceConfiguration;
		IMailQueue mailQueue;
		LoginResponses responses;
	}

	this(UserCollection userCollection, IMailQueue mailQueue,
			const LoginConfiguration configuration = LoginConfiguration(),
			const ServiceConfiguration serviceConfiguration = ServiceConfiguration()) {

		this.configuration = configuration;
		this.serviceConfiguration = serviceConfiguration;

		this.userCollection = userCollection;
		this.mailQueue = mailQueue;

		this.responses = new LoginResponses(configuration, serviceConfiguration);
	}

	void handler(HTTPServerRequest req, HTTPServerResponse res) {
		try {
			if(req.method == HTTPMethod.GET && req.path == configuration.paths.form) {
				responses.loginForm(req, res);
			}

			if(req.method == HTTPMethod.GET && req.path == configuration.paths.resetForm) {
				responses.resetForm(req, res);
			}

			if(req.method == HTTPMethod.POST && req.path == configuration.paths.login) {
				loginCheck(req, res);
			}

			if(req.method == HTTPMethod.POST && req.path == configuration.paths.reset) {
				reset(req, res);
			}

		} catch(Exception e) {
			version(unittest) {} else debug stderr.writeln(e);

			if(!res.headerWritten) {
				res.writeJsonBody([ "error": ["message": e.msg] ], 500);
			}
		}
	}

	private auto resetPasswordVariables() {
		string[string] variables;

		variables["reset"] = configuration.paths.resetForm;
		variables["location"] = serviceConfiguration.location;
		variables["serviceName"] = serviceConfiguration.name;

		return variables;
	}

	void reset(HTTPServerRequest req, HTTPServerResponse res) {
		auto requestData = const RequestUserData(req);

		const string message = `If your email address exists in our database, you will ` ~
			`receive a password recovery link at your email address in a few minutes.`;

		auto expire = Clock.currTime + 15.minutes;
		auto token = userCollection.createToken(requestData.username, expire, [], "passwordReset");

		auto user = userCollection[requestData.username];

		auto variables = resetPasswordVariables;
		variables["user.name"] = user.name;

		mailQueue.addResetPasswordMessage(user.email, token, variables);

		res.redirect(configuration.paths.form ~ "?username=" ~ requestData.username.encodeComponent ~
			"&message=" ~ message.encodeComponent);
	}

	void loginCheck(HTTPServerRequest req, HTTPServerResponse res) {
		auto requestData = const RequestUserData(req);

		if(!userCollection.contains(requestData.username)) {
			sleep(uniform(0, 500).msecs);
			res.redirect(configuration.paths.form ~ queryUserData(requestData, "Invalid username or password"));
			return;
		}

		if(!userCollection[requestData.username].isActive) {
			sleep(uniform(0, 500).msecs);
			res.redirect(configuration.paths.form ~ queryUserData(requestData, "Please confirm your account before you log in"));
			return;
		}

		if(!userCollection[requestData.username].isValidPassword(requestData.password)) {
			sleep(uniform(0, 500).msecs);
			res.redirect(configuration.paths.form ~ queryUserData(requestData, "Invalid username or password"));
			return;
		}

		auto scopes = userCollection[requestData.username].getScopes;
		auto expiration = Clock.currTime + configuration.loginTimeoutSeconds.seconds;

		auto token = userCollection[requestData.username].createToken(expiration, scopes, "webLogin");

		res.setCookie("auth-token", token.name);
		res.cookies["auth-token"].maxAge = configuration.loginTimeoutSeconds;

		res.redirect(configuration.paths.redirect);
	}

	private string queryUserData(const RequestUserData data, const string error = "") {
		return "?username=" ~ data.username.encodeComponent ~ (error != "" ? "&error=" ~ error.encodeComponent : "");
	}
}

version(unittest) {
	import http.request;
	import http.json;
	import bdd.base;
	import vibeauth.token;

	UserMemmoryCollection collection;
	User user;
	Client client;
	ClientCollection clientCollection;
	Token refreshToken;
	TestMailQueue mailQueue;

	class TestMailQueue : MailQueue
	{
		Message[] messages;

		this() {
			super(EmailConfiguration());
		}

		override
		void addMessage(Message message) {
			messages ~= message;
		}
	}

	auto testRouter() {
		auto router = new URLRouter();

		collection = new UserMemmoryCollection(["doStuff"]);
		user = new User("user@gmail.com", "password");
		user.name = "John Doe";
		user.username = "test";
		user.id = 1;
		user.isActive = true;

		collection.add(user);

		refreshToken = collection.createToken("user@gmail.com", Clock.currTime + 3600.seconds, ["doStuff", "refresh"], "Refresh");

		mailQueue = new TestMailQueue;
		auto auth = new LoginRoutes(collection, mailQueue);

		router.any("*", &auth.handler);

		return router;
	}
}

@("Login with valid username and password should redirect to root page")
unittest {
	testRouter
		.request.post("/login/check")
		.send(["username": "test", "password": "password"])
		.expectStatusCode(302)
		.expectHeader("Location", "/")
		.expectHeaderContains("Set-Cookie", "auth-token=")
		.end((Response res) => {
			res.headers["Set-Cookie"].should.contain(user.getTokensByType("webLogin").front.name);
		});
}

@("Login with valid email and password should redirect to root page")
unittest {
	testRouter
		.request.post("/login/check")
		.send(["username": "user@gmail.com", "password": "password"])
		.expectStatusCode(302)
		.expectHeader("Location", "/")
		.end();
}

@("Login with invalid username should redirect to login page")
unittest {
	testRouter
		.request.post("/login/check")
		.send(["username": "invalid", "password": "password"])
		.expectStatusCode(302)
		.expectHeader("Location", "/login?username=invalid&error=Invalid%20username%20or%20password")
		.end();
}

@("Login with inactive user")
unittest {
	auto router = testRouter;

	user.isActive = false;

	router
		.request.post("/login/check")
		.send(["username": "test", "password": "password"])
		.expectStatusCode(302)
		.expectHeader("Location", "/login?username=test&error=Please%20confirm%20your%20account%20before%20you%20log%20in")
		.end();
}

@("Login with invalid password should redirect to login page")
unittest {
	testRouter
		.request.post("/login/check")
		.send(["username": "test", "password": "invalid"])
		.expectStatusCode(302)
		.expectHeader("Location", "/login?username=test&error=Invalid%20username%20or%20password")
		.end();
}

@("Reset password form should send an email to existing user")
unittest {
	string expectedMessage = `If your email address exists in our database, you ` ~
	`will receive a password recovery link at your email address in a few minutes.`;

	testRouter
		.request.post("/login/reset/send")
		.send(["email": "user@gmail.com"])
		.expectStatusCode(302)
		.expectHeader("Location", "/login?username=user%40gmail.com&message=" ~ expectedMessage.encodeComponent)
		.end((Response res) => {
			string resetLink = "http://localhost/login/reset?email=user@gmail.com&token="
				~ collection["user@gmail.com"].getTokensByType("passwordReset").front.name;

			mailQueue.messages.length.should.equal(1);
			mailQueue.messages[0].textMessage.should.contain(resetLink);
			mailQueue.messages[0].htmlMessage.should.contain(`<a href="` ~ resetLink ~ `">`);
		});
}
