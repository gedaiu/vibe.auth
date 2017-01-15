module vibeauth.router.oauth;

import vibe.http.router;
import vibe.data.json;
import vibe.inet.url;

import std.algorithm, std.base64, std.string, std.stdio, std.conv, std.array;
import std.datetime;

import vibeauth.users;
import vibeauth.router.baseAuthRouter;
import vibeauth.client;
import vibeauth.collection;

import vibeauth.router.accesscontrol;


struct OAuth2Configuration {
	string tokenPath = "/auth/token";
	string authorizePath = "/auth/authorize";
	string authenticatePath = "/auth/authenticate";
	string revokePath = "/auth/revoke";

	string style = "";
}

struct AuthData {
	string username;
	string password;
	string refreshToken;
	string[] scopes;
}

interface IGrantAccess {
	void authData(AuthData authData);
	void userCollection(UserCollection userCollection);

	bool isValid();
	Json get();
}

final class UnknownGrantAccess : IGrantAccess{
	void authData(AuthData) {}
	void userCollection(UserCollection) {};

	bool isValid() {
		return false;
	}

	Json get() {
		auto response = Json.emptyObject;
		response["error"] = "Invalid `grant_type` value";

		return response;
	}
}

final class PasswordGrantAccess : IGrantAccess {
	private {
		AuthData data;
		UserCollection collection;
	}

	void authData(AuthData authData) {
		this.data = authData;
	}

	void userCollection(UserCollection userCollection) {
		this.collection = userCollection;
	}

	bool isValid() {
		if(!collection.contains(data.username)) {
			return false;
		}

		if(!collection[data.username].isValidPassword(data.password)) {
			return false;
		}

		return true;
	}

	Json get() {
		auto response = Json.emptyObject;

		if(!isValid) {
			response["error"] = "Invalid password or username";
			return response;
		}

		auto accessToken = collection.createToken(data.username, Clock.currTime + 3601.seconds, data.scopes, "Bearer");
		auto refreshToken = collection.createToken(data.username, Clock.currTime + 30.weeks, data.scopes ~ [ "refresh" ], "Refresh");

		response["access_token"] = accessToken.name;
		response["expires_in"] = (accessToken.expire - Clock.currTime).total!"seconds";
		response["token_type"] = accessToken.type;
		response["refresh_token"] = refreshToken.name;

		return response;
	}
}

final class RefreshTokenGrantAccess : IGrantAccess {
	private {
		AuthData data;
		UserCollection collection;
		User user;
	}

	void authData(AuthData authData) {
		this.data = authData;
		cacheData;
	}

	void userCollection(UserCollection userCollection) {
		this.collection = userCollection;
		cacheData;
	}

	private void cacheData() {
		if(collection is null || data.refreshToken == "") {
			return;
		}

		user = collection.byToken(data.refreshToken);
		data.scopes = user.getScopes(data.refreshToken).filter!(a => a != "refresh").array;
	}

	bool isValid() {
		if(data.refreshToken == "") {
			return false;
		}

		return user.isValidToken(data.refreshToken, "refresh");
	}

	Json get() {
		auto response = Json.emptyObject;

		if(!isValid) {
			response["error"] = "Invalid `refresh_token`";
			return response;
		}

		auto username = user.email();

		auto accessToken = collection.createToken(username, Clock.currTime + 3601.seconds, data.scopes, "Bearer");

		response["access_token"] = accessToken.name;
		response["expires_in"] = (accessToken.expire - Clock.currTime).total!"seconds";
		response["token_type"] = accessToken.type;

		return response;
	}
}

IGrantAccess getAuthData(HTTPServerRequest req) {
	AuthData data;

	if("refresh_token" in req.form) {
		data.refreshToken = req.form["refresh_token"];
	}

	if("username" in req.form) {
		data.username = req.form["username"];
	}

	if("password" in req.form) {
		data.password = req.form["password"];
	}

	if("scope" in req.form) {
		data.scopes = req.form["scope"].split(" ");
	}

	if("grant_type" in req.form) {
		if(req.form["grant_type"] == "password") {
			auto grant = new PasswordGrantAccess;
			grant.authData = data;

			return grant;
		}

		if(req.form["grant_type"] == "refresh_token") {
			auto grant = new RefreshTokenGrantAccess;
			grant.authData = data;

			return grant;
		}
	}


	return new UnknownGrantAccess;
}

class OAuth2: BaseAuthRouter {
	protected {
		const OAuth2Configuration configuration;
		ClientCollection clientCollection;
	}

	this(UserCollection userCollection, ClientCollection clientCollection, const OAuth2Configuration configuration = OAuth2Configuration()) {
		super(userCollection);

		this.configuration = configuration;
		this.clientCollection = clientCollection;
	}

	override {
		void checkLogin(HTTPServerRequest req, HTTPServerResponse res) {
			try {
				setAccessControl(res);
				if(req.method == HTTPMethod.OPTIONS) {
					return;
				}

				if(req.path == configuration.tokenPath) {
					createToken(req, res);
				}

				if (req.path == configuration.authorizePath) {
					authorize(req, res);
				}

				if(req.path == configuration.authenticatePath) {
					authenticate(req, res);
				}

				if(req.path == configuration.revokePath) {
					revoke(req, res);
				}

				if(!res.headerWritten && req.path != configuration.style && !isValidBearer(req)) {
					respondUnauthorized(res);
				}
			} catch(Exception e) {
				version(unittest) {} else debug stderr.writeln(e);

				if(!res.headerWritten) {
					res.writeJsonBody([ "error": e.msg ], 500);
				}
			}
		}
	}

	private {
		bool isValidBearer(HTTPServerRequest req) {
			auto pauth = "Authorization" in req.headers;

			if(pauth && (*pauth).startsWith("Bearer ")) {
				auto token = (*pauth)[7 .. $];

				try {
					auto const user = collection.byToken(token);
					req.username = user.email;
				} catch(UserNotFoundException exception) {
					return false;
				}

				return true;
			}

			return false;
		}

		void authorize(HTTPServerRequest req, HTTPServerResponse res) {
			if("redirect_uri" !in req.query) {
				showError(res, "Missing `redirect_uri` parameter");
				return;
			}

			if("client_id" !in req.query) {
				showError(res, "Missing `client_id` parameter");
				return;
			}

			if("state" !in req.query) {
				showError(res, "Missing `state` parameter");
				return;
			}

			auto const redirectUri = req.query["redirect_uri"];
			auto const clientId = req.query["client_id"];
			auto const state = req.query["state"];
			auto const style = configuration.style;

			if(clientId !in clientCollection) {
				showError(res, "Invalid `client_id` parameter");
				return;
			}

			string appTitle = clientCollection[clientId].name;

			res.render!("loginForm.dt", appTitle, redirectUri, state, style);
		}

		void showError(HTTPServerResponse res, const string error) {
			auto const style = configuration.style;
			res.statusCode = 400;
			res.render!("error.dt", error, style);
		}

		void authenticate(HTTPServerRequest req, HTTPServerResponse res) {
			string email;
			string password;

			try {
				email = req.form["email"];
				password = req.form["password"];
			} catch (Exception e) {
				debug showError(res, e.to!string);
				return;
			}

			if(!collection.contains(email) || !collection[email].isValidPassword(password)) {
				showError(res, "Invalid email or password.");
				return;
			}

			auto token = collection[email].createToken(Clock.currTime + 3601.seconds);
			auto redirectUri = req.form["redirect_uri"] ~ "#access_token=" ~ token.name ~ "&state=" ~ req.form["state"];

			res.render!("redirect.dt", redirectUri);
		}

		void createToken(HTTPServerRequest req, HTTPServerResponse res) {
			auto grant = req.getAuthData;
			grant.userCollection = collection;

			res.statusCode = grant.isValid ? 200 : 401;
			res.writeJsonBody(grant.get);
		}

		void revoke(HTTPServerRequest req, HTTPServerResponse res) {
			auto const token = req.form["token"];
			collection.revoke(token);
		}

		void respondUnauthorized(HTTPServerResponse res, string message = "Authorization required") {
			res.statusCode = HTTPStatus.unauthorized;
			res.writeJsonBody([ "error": message ]);
		}
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
	OAuth2 auth;
	Token refreshToken;

	auto testRouter() {
		auto router = new URLRouter();

		collection = new UserMemmoryCollection(["doStuff"]);
		user = new User("user@gmail.com", "password");
		user.name = "John Doe";
		user.username = "test";
		user.id = 1;

		collection.add(user);

		refreshToken = collection.createToken("user@gmail.com", Clock.currTime + 3600.seconds, ["doStuff", "refresh"], "Refresh");

		auto client = new Client();
		client.id = "CLIENT_ID";

		clientCollection = new ClientCollection([ client ]);

		auth = new OAuth2(collection, clientCollection);
		router.any("*", &auth.checkLogin);

		return router;
	}
}

@("it should return 401 on missing auth")
unittest {
	testRouter.request.get("/sites").expectStatusCode(401).end();
}

@("it should return 401 on invalid credentials")
unittest {
	testRouter
		.request.post("/auth/token")
		.send(["grant_type": "password", "username": "invalid", "password": "invalid"])
		.expectStatusCode(401)
		.end;
}

@("it should return tokens on valid email and password")
unittest {
	testRouter
		.request
		.post("/auth/token")
		.send(["grant_type": "password", "username": "user@gmail.com", "password": "password"])
		.expectStatusCode(200)
		.end((Response response) => {
			response.bodyJson.keys.should.contain(["access_token", "expires_in", "refresh_token", "token_type"]);

			user.isValidToken(response.bodyJson["access_token"].to!string).should.be.equal(true);
			user.isValidToken(response.bodyJson["refresh_token"].to!string).should.be.equal(true);

			response.bodyJson["token_type"].to!string.should.equal("Bearer");
			response.bodyJson["expires_in"].to!int.should.equal(3600);
		});
}


@("it should return tokens on valid username and password")
unittest {
	testRouter
		.request
		.post("/auth/token")
		.send(["grant_type": "password", "username": "test", "password": "password"])
		.expectStatusCode(200)
		.end((Response response) => {
			response.bodyJson.keys.should.contain(["access_token", "expires_in", "refresh_token", "token_type"]);

			user.isValidToken(response.bodyJson["access_token"].to!string).should.be.equal(true);
			user.isValidToken(response.bodyJson["refresh_token"].to!string).should.be.equal(true);

			response.bodyJson["token_type"].to!string.should.equal("Bearer");
			response.bodyJson["expires_in"].to!int.should.equal(3600);
		});
}

@("it should set the scope tokens on valid credentials")
unittest {
	testRouter
		.request
		.post("/auth/token")
		.send(["grant_type": "password", "username": "user@gmail.com", "password": "password", "scope": "access1 access2"])
		.expectStatusCode(200)
		.end((Response response) => {
			user.isValidToken(response.bodyJson["refresh_token"].to!string, "refresh").should.equal(true);
			user.isValidToken(response.bodyJson["refresh_token"].to!string, "other").should.equal(false);

			user.isValidToken(response.bodyJson["access_token"].to!string, "access1").should.equal(true);
			user.isValidToken(response.bodyJson["access_token"].to!string, "access2").should.equal(true);
			user.isValidToken(response.bodyJson["access_token"].to!string, "other").should.equal(false);
		});
}

@("it should return a new access token on ")
unittest {
	auto router = testRouter;

	router
		.request
		.post("/auth/token")
		.send(["grant_type": "refresh_token", "refresh_token": refreshToken.name ])
		.expectStatusCode(200)
		.end((Response response) => {
			response.bodyJson.keys.should.contain(["access_token", "expires_in", "token_type"]);

			user.isValidToken(response.bodyJson["access_token"].to!string).should.be.equal(true);
			user.isValidToken(response.bodyJson["access_token"].to!string, "doStuff").should.be.equal(true);
			user.isValidToken(response.bodyJson["access_token"].to!string, "refresh").should.be.equal(false);

			response.bodyJson["token_type"].to!string.should.equal("Bearer");
			response.bodyJson["expires_in"].to!int.should.equal(3600);
		});
}
