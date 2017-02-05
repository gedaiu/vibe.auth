module vibeauth.router.login;

import vibe.http.router;
import vibe.data.json;
import vibe.inet.url;

import std.algorithm, std.base64, std.string, std.stdio, std.conv, std.array;
import std.datetime;

import vibeauth.users;
import vibeauth.router.baseAuthRouter;
import vibeauth.client;
import vibeauth.collection;
import vibeauth.templatehelper;

import vibeauth.router.accesscontrol;

struct LoginConfiguration {
	string formPath = "/login";
	string style = "";
}

class LoginRoutes {

	private {
		UserCollection userCollection;
		LoginConfiguration configuration;

		immutable string loginFormPage;
	}

	this(UserCollection userCollection, const LoginConfiguration configuration = LoginConfiguration()) {
		this.configuration = configuration;
		this.userCollection = userCollection;

		this.loginFormPage = prepareLoginPage;
	}

	string prepareLoginPage() {
		const defaultDestination = import("login/template.html");
		const form = import("login/form.html");

		return defaultDestination.replace("#{body}", form).replaceVariables(configuration.serializeToJson);
	}

	void handler(HTTPServerRequest req, HTTPServerResponse res) {
		try {
			if(req.method == HTTPMethod.GET && req.path == configuration.formPath) {
				loginForm(req, res);
			}
		} catch(Exception e) {
			version(unittest) {} else debug stderr.writeln(e);

			if(!res.headerWritten) {
				res.writeJsonBody([ "error": ["message": e.msg] ], 500);
			}
		}
	}

	void loginForm(HTTPServerRequest req, HTTPServerResponse res) {
		res.writeBody(loginFormPage, 200, "text/html; charset=UTF-8" );
	}
}
