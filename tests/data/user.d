module vibeauth.tests.data.user;

import fluent.asserts;
import vibeauth.data.user;
import std.uuid;
import std.datetime;
import std.conv;
import vibe.data.json;

/// Password validation
unittest {
  auto user = new User("user", "password");
  auto password = user.toJson["password"].to!string;
  auto salt = user.toJson["salt"].to!string;

  password.should.equal(sha1UUID(salt ~ ".password").to!string);
  user.isValidPassword("password").should.equal(true);
  user.isValidPassword("other passowrd").should.equal(false);
}

/// Converting a user to a public json
unittest {
  auto user = new User("user", "password");
  auto json = user.toPublicJson;

  assert("id" in json, "It should contain the id");
  assert("name" in json, "It should contain the name");
  assert("username" in json, "It should contain the username");
  assert("email" in json, "It should contain the email");
  assert("password" !in json, "It should not contain the password");
  assert("salt" !in json, "It should not contain the salt");
  assert("scopes" in json, "It should contain the scope");
  assert("tokens" !in json, "It should not contain the tokens");
}

/// User serialization
unittest {
  auto user = new User("user", "password");
  auto json = user.toJson;

  assert("_id" in json, "It should contain the id");
  assert("email" in json, "It should contain the email");
  assert("password" in json, "It should contain the password");
  assert("salt" in json, "It should contain the salt");
  assert("scopes" in json, "It should contain the scope");
  assert("tokens" in json, "It should contain the tokens");
}

/// User data deserialization
unittest {
  auto json = `{
    "_id": "1",
    "name": "name",
    "username": "username",
    "email": "test@asd.asd",
    "password": "password",
    "salt": "salt",
    "isActive": true,
    "scopes": ["scopes"],
    "tokens": [ { "name": "token", "expire": "2100-01-01T00:00:00", "scopes": [], "type": "Bearer" }],
  }`.parseJsonString;


  auto user = User.fromJson(json);
  auto juser = user.toJson;

  assert(user.id == "1", "It should deserialize the id");
  assert(user.name == "name", "It should deserialize the name");
  assert(user.username == "username", "It should deserialize the username");
  assert(user.email == "test@asd.asd", "It should deserialize the email");
  assert(juser["password"] == "password", "It should deserialize the password");
  assert(juser["salt"] == "salt", "It should deserialize the salt");
  assert(juser["isActive"] == true, "It should deserialize the isActive field");
  assert(juser["scopes"][0] == "scopes", "It should deserialize the scope");
  assert(juser["tokens"][0]["name"] == "token", "It should deserialize the tokens");
}

/// Change event
unittest {
  auto user = new User();
  auto changed = false;

  void userChanged(User u) {
    changed = true;
  }

  user.onChange = &userChanged;

  user.id = 1;
  assert(changed, "onChange should be called when the id is changed");

  changed = false;
  user.email = "email";
  assert(changed, "onChange should be called when the email is changed");

  changed = false;
  user.setPassword("password");
  assert(changed, "onChange should be called when the password is changed");

  changed = false;
  user.setPassword("password", "salt");
  assert(changed, "onChange should be called when the password is changed");

  changed = false;
  user.createToken(Clock.currTime + 3600.seconds);
  assert(changed, "onChange should be called when a token is created");
}
