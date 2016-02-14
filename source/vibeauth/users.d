module vibeauth.users;

import vibe.data.json;

import std.stdio;
import std.algorithm.searching;
import std.algorithm.iteration;
import std.exception;
import std.uuid;
import std.conv;
import std.datetime;

import vibeauth.collection;

alias UserNotFoundException = ItemNotFoundException;

class UserAccesNotFoundException : Exception {
  this(string msg = null, Throwable next = null) { super(msg, next); }
  this(string msg, string file, size_t line, Throwable next = null) {
    super(msg, file, line, next);
  }
}

class User {
  alias ChangedEvent = void delegate(User);

  ChangedEvent onChange;

  private {
  	ulong _id;
    string _email;
    string password;
    string salt;
  }

	string[] scopes;
	string[] tokens;

  this() { }

	this(string email, string password) {
		this.email = email;
    setPassword(password);
	}

  @property {
    auto id() const {
      return _id;
    }

    void id(ulong value) {
      _id = value;
      if(onChange) {
        onChange(this);
      }
    }

    auto email() const {
      return _email;
    }

    void email(string value) {
      _email = value;
      if(onChange) {
        onChange(this);
      }
    }
  }

	const {
		bool can(string access)() {
			return scopes.canFind(access);
		}

		bool isValidPassword(string password) {
			return sha1UUID(salt ~ "." ~ password).to!string == this.password;
		}

		bool isValidToken(string token) {
			return tokens.canFind(token);
		}
	}

  void setPassword(string password) {
    this.salt = randomUUID.to!string;
		this.password = sha1UUID(salt ~ "." ~ password).to!string;

    if(onChange) {
      onChange(this);
    }
  }

  void setPassword(string password, string salt) {
    this.salt = salt;
		this.password = password;

    if(onChange) {
      onChange(this);
    }
  }

	string createToken() {
		auto token = randomUUID.to!string;
		tokens ~= token;

    if(onChange) {
      onChange(this);
    }

    return token;
	}

  Json toJson() const {
    Json data = toPublicJson;

    data.password = password;
    data.salt = salt;
    data.tokens = Json.emptyArray;

    foreach(token; tokens) {
      data["tokens"] ~= token;
    }

    return data;
  }

  Json toPublicJson() const {
    Json data = Json.emptyObject;

    data.id = id;
    data.email = email;
    data["scope"] = Json.emptyArray;

    foreach(s; scopes) {
      data["scope"] ~= s;
    }

    return data;
  }

  static User fromJson(Json data) {
    auto user = new User();

    user.id = data.id.to!long;
    user.email = data.email.to!string;
    user.setPassword(data.password.to!string, data.salt.to!string);

    foreach(s; data["scope"]) {
      user.scopes ~= s.to!string;
    }

    foreach(token; data["tokens"]) {
      user.tokens ~= token.to!string;
    }

    return user;
  }
}

class UserCollection: Collection!User {
  long index = 0;
	immutable(string[]) accessList;

  alias opBinaryRight = Collection!User.opBinaryRight;
  alias opIndex = Collection!User.opIndex;

	this(immutable(string[]) accessList, User[] list = []) {
		this.accessList = accessList;
    super(list);
	}

	void empower(string email, string access) {
		auto user = this[email];

		enforce!UserAccesNotFoundException(accessList.canFind(access), "`" ~ access ~ "` it's not in the list");

		user.scopes ~= access;
	}

  override {
    User opIndex(string email) {
  		auto list = list.find!(a => a.email == email);

  		enforce!UserNotFoundException(list.count > 0, "User not found");

  		return list[0];
  	}
  }

	User byToken(string token) {
		auto list = list.find!(a => a.isValidToken(token));

		enforce!UserNotFoundException(list.count > 0, "User not found");

		return list[0];
	}

  bool contains(string email) {
    return !list.filter!(a => a.email == email).empty;
  }
}

unittest {
	auto collection = new UserCollection([]);
	auto user = new User("user", "password");

	collection.add(user);
	assert(collection["user"] == user, "It should return user by name");
	assert(collection.contains("user"), "It should find user by name");
	assert(!collection.contains("other user"), "It should not find user by name");

	bool thwrown;

	try {
		collection["other user"];
	} catch (Exception e) {
		thwrown = true;
	}

	assert(thwrown, "It should raise exception when the user it's not found");
}

unittest {
	auto user = new User("user", "password");

	assert(user.password == sha1UUID(user.salt ~ ".password").to!string, "It should salt the password");
	assert(user.isValidPassword("password"), "It should return true for a valid password");
	assert(!user.isValidPassword("other passowrd"), "It should return false for an invalid password");
}

unittest {
  auto user = new User("user", "password");
  auto json = user.toPublicJson;

  assert("id" in json, "It should contain the id");
  assert("email" in json, "It should contain the email");
  assert("password" !in json, "It should not contain the password");
  assert("salt" !in json, "It should not contain the salt");
  assert("scope" in json, "It should contain the scope");
  assert("tokens" !in json, "It should not contain the tokens");
}

unittest {
  auto user = new User("user", "password");
  auto json = user.toJson;

  assert("id" in json, "It should contain the id");
  assert("email" in json, "It should contain the email");
  assert("password" in json, "It should contain the password");
  assert("salt" in json, "It should contain the salt");
  assert("scope" in json, "It should contain the scope");
  assert("tokens" in json, "It should contain the tokens");
}

unittest {
  auto json = `{
    "id": 1,
    "email": "test@asd.asd",
    "password": "password",
    "salt": "salt",
    "scope": ["scope"],
    "tokens": ["token"],
  }`.parseJsonString;


  auto user = User.fromJson(json);

  assert(user.id == 1, "It should deserialize the id");
  assert(user.email == "test@asd.asd", "It should deserialize the email");
  assert(user.password == "password", "It should deserialize the password");
  assert(user.salt == "salt", "It should deserialize the salt");
  assert(user.scopes[0] == "scope", "It should deserialize the scope");
  assert(user.tokens[0] == "token", "It should deserialize the tokens");
}

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
  user.createToken();
  assert(changed, "onChange should be called when a token is created");
}

unittest {
	auto collection = new UserCollection(["doStuff"]);
	auto user = new User("user", "password");
  user.id = 1;

	auto otherUser = new User("otherUser", "password");
  otherUser.id = 2;

	collection.add(user);
	collection.add(otherUser);
	collection.empower("user", "doStuff");

  assert(user.can!"doStuff", "It should return true if the user can `doStuff`");
  assert(!otherUser.can!"doStuff", "It should return false if the user can not `doStuff`");
  assert(collection[1] == user, "It should find user by id");
}

unittest {
	auto collection = new UserCollection([]);
	auto user = new User("user", "password");

	collection.add(user);
	auto token = user.createToken;

	assert(collection.byToken(token) == user, "It should find user by token");

	bool thwrown;

	try {
		collection.byToken("token");
	} catch (Exception e) {
		thwrown = true;
	}

	assert(thwrown, "It should raise exception when an user it's not found by token");
}

unittest {
	auto collection = new UserCollection([]);
	auto user = new User("user", "password");
  user.id = 1;

	collection.add(user);
  collection.remove(1);

	assert(collection.length == 0, "It should remove user by id");
}
