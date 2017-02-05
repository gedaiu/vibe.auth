module vibeauth.router.login;

import vibe.http.router;
import vibe.data.json;
import vibe.inet.url;

import std.algorithm, std.base64, std.string, std.stdio, std.conv, std.array;
import std.datetime, std.random, std.uri;
import vibe.core.core;

import vibeauth.users;
import vibeauth.router.baseAuthRouter;
import vibeauth.client;
import vibeauth.collection;
import vibeauth.templatehelper;
import vibeauth.router.accesscontrol;
import vibeauth.router.request;

struct LoginConfiguration {
	string formPath = "/login";
	string loginPath = "/login/check";
	string redirectPath = "/";

	ulong loginTimeoutSeconds = 86_400;

	string style = "";
}

class LoginRoutes {

	private {
		UserCollection userCollection;
		LoginConfiguration configuration;

		immutable string loginFormTemplate;
	}

	this(UserCollection userCollection, const LoginConfiguration configuration = LoginConfiguration()) {
		this.configuration = configuration;
		this.userCollection = userCollection;

		this.loginFormTemplate = prepareLoginTemplate;
	}

	string prepareLoginTemplate() {
		const defaultDestination = import("login/template.html");
		const form = import("login/form.html");

		return defaultDestination.replace("#{body}", form).replaceVariables(configuration.serializeToJson);
	}

	void handler(HTTPServerRequest req, HTTPServerResponse res) {
		try {
			if(req.method == HTTPMethod.GET && req.path == configuration.formPath) {
				loginForm(req, res);
			}

			if(req.method == HTTPMethod.POST && req.path == configuration.loginPath) {
				loginCheck(req, res);
			}

		} catch(Exception e) {
			version(unittest) {} else debug stderr.writeln(e);

			if(!res.headerWritten) {
				res.writeJsonBody([ "error": ["message": e.msg] ], 500);
			}
		}
	}

	void loginForm(HTTPServerRequest req, HTTPServerResponse res) {
		auto requestData = const RequestUserData(req);
		Json data = Json.emptyObject;

		data["email"] = requestData.email;
		data["error"] = requestData.error == "" ? "" :
			`<div class="alert alert-danger" role="alert">` ~ requestData.error ~ `</div>`;

		string loginFormPage = loginFormTemplate.replaceVariables(data);

		res.writeBody(loginFormPage, 200, "text/html; charset=UTF-8" );
	}

	void loginCheck(HTTPServerRequest req, HTTPServerResponse res) {
		auto requestData = const RequestUserData(req);

		if(!userCollection.contains(requestData.username)) {
			sleep(uniform(0, 500).msecs);
			res.redirect(configuration.formPath ~ queryUserData(requestData, "Invalid username or password"));
			return;
		}

		if(!userCollection[requestData.username].isActive) {
			sleep(uniform(0, 500).msecs);
			res.redirect(configuration.formPath ~ queryUserData(requestData, "Please confirm your account before you log in"));
			return;
		}

		if(!userCollection[requestData.username].isValidPassword(requestData.password)) {
			sleep(uniform(0, 500).msecs);
			res.redirect(configuration.formPath ~ queryUserData(requestData, "Invalid username or password"));
			return;
		}

		auto scopes = userCollection[requestData.username].getScopes;
		auto expiration = Clock.currTime + configuration.loginTimeoutSeconds.seconds;

		auto token = userCollection[requestData.username].createToken(expiration, scopes, "webLogin");

		res.setCookie("auth-token", token.name);
		res.cookies["auth-token"].maxAge = configuration.loginTimeoutSeconds;

		res.redirect(configuration.redirectPath);
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

		auto auth = new LoginRoutes(collection);

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
