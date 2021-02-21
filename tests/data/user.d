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
  assert("firstName" in json, "It should contain the first name");
  assert("lastName" in json, "It should contain the last name");
  assert("salutation" in json, "It should contain the salutation");
  assert("title" in json, "It should contain the title");
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
  assert("createdAt" in json, "It should contain the createdAt");
}

/// User data deserialization
unittest {
  auto json = `{
    "_id": "1",
    "firstName": "firstName",
    "lastName": "lastName",
    "title": "title",
    "salutation": "salutation",
    "username": "username",
    "email": "test@asd.asd",
    "password": "password",
    "salt": "salt",
    "isActive": true,
    "createdAt": "2000-01-01T00:00:00",
    "scopes": ["scopes"],
    "tokens": [ { "name": "token", "expire": "2100-01-01T00:00:00", "scopes": [], "type": "Bearer" }],
  }`.parseJsonString;


  auto user = User.fromJson(json);

  user.id.should.equal("1");
  user.firstName.should.equal("firstName");
  user.lastName.should.equal("lastName");
  user.title.should.equal("title");
  user.salutation.should.equal("salutation");
  user.username.should.equal("username");
  user.email.should.equal("test@asd.asd");

  user.toJson.should.equal(`{
    "email": "test@asd.asd",
    "username": "username",
    "lastActivity": 0,
    "scopes": [ "scopes" ],
    "isActive": true,
    "createdAt": "2000-01-01T00:00:00",
    "salt": "salt",
    "firstName": "firstName",
    "lastName": "lastName",
    "title": "title",
    "salutation": "salutation",
    "_id": "1",
    "lastActivity": 0,
    "password": "password",
    "tokens": [{
      "scopes": [],
      "type": "Bearer",
      "meta": {},
      "expire": "2100-01-01T00:00:00",
      "name": "token"
    }]}`.parseJsonString);
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
