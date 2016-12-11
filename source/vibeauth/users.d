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

struct UserData {
  	string id;
    string email;
    string password;
    string salt;

    string[] scopes;
    string[] tokens;
}

class User {
  alias ChangedEvent = void delegate(User);

  ChangedEvent onChange;

  private {
    UserData userData;
  }

  this() { }

  this(UserData userData) {
    this.userData = userData;
  }

	this(string email, string password) {
		this.userData.email = email;
    setPassword(password);
	}

  @property {
    auto id() const {
      return userData.id;
    }

    void id(ulong value) {
      userData.id = value.to!string;

      if(onChange) {
        onChange(this);
      }
    }

    auto email() const {
      return userData.email;
    }

    void email(string value) {
      userData.email = value;

      if(onChange) {
        onChange(this);
      }
    }
  }

  override
  string toString() {
    return toJson.toPrettyString;
  }

	const {
		bool can(string access)() {
			return userData.scopes.canFind(access);
		}

		bool isValidPassword(string password) {
			return sha1UUID(userData.salt ~ "." ~ password).to!string == userData.password;
		}

		bool isValidToken(string token) {
			return userData.tokens.canFind(token);
		}
	}

  void setPassword(string password) {
    userData.salt = randomUUID.to!string;
		userData.password = sha1UUID(userData.salt ~ "." ~ password).to!string;

    if(onChange) {
      onChange(this);
    }
  }

  void setPassword(string password, string salt) {
    userData.salt = salt;
		userData.password = password;

    if(onChange) {
      onChange(this);
    }
  }

  void addScope(string access) {
    userData.scopes ~= access;
  }

	string createToken() {
		auto token = randomUUID.to!string;
		userData.tokens ~= token;

    if(onChange) {
      onChange(this);
    }

    return token;
	}

  Json toJson() const {
    return userData.serializeToJson;
  }

  Json toPublicJson() const {
    Json data = Json.emptyObject;

    data["id"] = id;
    data["email"] = email;
    data["scopes"] = Json.emptyArray;

    foreach(s; userData.scopes) {
      data["scopes"] ~= s;
    }

    return data;
  }

  static User fromJson(Json data) {
    return new User(data.deserializeJson!UserData);
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

		user.addScope(access);
	}

  override {
    User opIndex(string email) {
  		auto result = list.find!(a => a.email == email);

  		enforce!UserNotFoundException(result.count > 0, "User not found");

  		return result[0];
  	}
  }

	User byToken(string token) {
		auto result = list.find!(a => a.isValidToken(token));

		enforce!UserNotFoundException(result.count > 0, "User not found");

		return result[0];
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
  auto password = user.toJson["password"].to!string;
  auto salt = user.toJson["salt"].to!string;

	assert(password == sha1UUID(salt ~ ".password").to!string, "It should salt the password");
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
  assert("scopes" in json, "It should contain the scope");
  assert("tokens" !in json, "It should not contain the tokens");
}

unittest {
  auto user = new User("user", "password");
  auto json = user.toJson;

  assert("id" in json, "It should contain the id");
  assert("email" in json, "It should contain the email");
  assert("password" in json, "It should contain the password");
  assert("salt" in json, "It should contain the salt");
  assert("scopes" in json, "It should contain the scope");
  assert("tokens" in json, "It should contain the tokens");
}

unittest {
  auto json = `{
    "id": 1,
    "email": "test@asd.asd",
    "password": "password",
    "salt": "salt",
    "scopes": ["scopes"],
    "tokens": ["token"],
  }`.parseJsonString;


  auto user = User.fromJson(json);
  auto juser = user.toJson;

  assert(user.id == 1, "It should deserialize the id");
  assert(user.email == "test@asd.asd", "It should deserialize the email");
  assert(juser["password"] == "password", "It should deserialize the password");
  assert(juser["salt"] == "salt", "It should deserialize the salt");
  assert(juser["scopes"][0] == "scopes", "It should deserialize the scope");
  assert(juser["tokens"][0] == "token", "It should deserialize the tokens");
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
