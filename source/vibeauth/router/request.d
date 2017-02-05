module vibeauth.router.request;

import vibeauth.users;

import vibe.http.router;
import vibe.data.json;
import vibe.inet.url;

import std.string;

const struct RequestUserData {
	private {
		const string[string] data;
	}

	this(HTTPServerRequest req) const {
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

		this.data = data;
	}

	private string get(string field)() {
		return field in data ? data[field] : "";
	}

	Json toJson() {
		Json response = data.serializeToJson;

		if("error" !in response) {
			response["error"] = "";
		}

		if("name" !in response) {
			response["name"] = "";
		}

		if("username" !in response) {
			response["username"] = "";
		}

		if("email" !in response) {
			response["email"] = "";
		}


		return response;
	}

	string[] getMissingFields(string[] fields) const {
		string[] missingFields;

		foreach(field; fields) {
			if(field !in data) {
				missingFields ~= field;
			}
		}

		return missingFields;
	}

	string name() {
		return get!"name";
	}

	string username() {
		return get!"username";
	}

	string email() {
		return get!"email";
	}

	string response() {
		return get!"response";
	}

	string password() {
		return get!"password";
	}

	string error() {
		return get!"error";
	}

	void validateUser() {
		auto missingFields = getMissingFields(["name", "username", "email", "password", "response"]);

		if(missingFields.length == 1) {
			throw new Exception("`" ~ missingFields[0] ~ "` is missing");
		}

		if(missingFields.length > 1) {
			throw new Exception("`" ~ missingFields.join(",") ~ "` is missing");
		}

		if(password == "") {
			throw new Exception("The `password` is empty");
		}

		if(password.length < 10) {
			throw new Exception("The `password` should have at least 10 chars");
		}
	}
}


User user(HTTPServerRequest req, UserCollection collection) {
	string token = req.cookies.get("auth-token");

	User user;

	if(token !is null) {
		try {
			user = collection.byToken(token);
		} catch(Exception) {
			return null;
		}
	}

	return user;
}
