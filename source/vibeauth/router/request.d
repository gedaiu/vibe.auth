module vibeauth.router.request;

import vibeauth.collections.usercollection;
import vibeauth.data.user;

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

    foreach(pair; req.query.byKeyValue) {
      auto value = pair.value.strip;

      if(value.length > 0) {
        data[pair.key] = value;
      }
    }

    foreach(pair; req.form.byKeyValue) {
      auto value = pair.value.strip;

      if(value.length > 0) {
        data[pair.key] = value;
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

  string passwordConfirm() {
    return get!"passwordConfirm";
  }

  string error() {
    return get!"error";
  }

  string message() {
    return get!"message";
  }

  string token() {
    return get!"token";
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

User getUser(HTTPServerRequest req, UserCollection collection) {
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

/// Remove all user data fields from the request
void cleanRequest(HTTPServerRequest req) {
  req.username = "";
  req.password = "";

  if("email" in req.context) {
    req.context.remove("email");
  }
}
