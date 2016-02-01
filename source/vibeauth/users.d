module vibeauth.users;

import vibe.data.json;

import std.stdio;
import std.algorithm.searching;
import std.algorithm.iteration;
import std.exception;
import std.uuid;
import std.conv;
import std.datetime;

class UserNotFoundException : Exception {
  this(string msg = null, Throwable next = null) { super(msg, next); }
  this(string msg, string file, size_t line, Throwable next = null) {
    super(msg, file, line, next);
  }
}

class UserAccesNotFoundException : Exception {
  this(string msg = null, Throwable next = null) { super(msg, next); }
  this(string msg, string file, size_t line, Throwable next = null) {
    super(msg, file, line, next);
  }
}

class User {
	ulong id;
	string email;

  private {
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
  }

  void setPassword(string password, string salt) {
    this.salt = salt;
		this.password = password;
  }

	string createToken() {
		auto token = randomUUID.to!string;
		tokens ~= token;

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

class UserCollection {
  long index = 0;
	immutable(string[]) accessList;

	protected User[] userList;

	this(immutable(string[]) accessList, User[] userList = []) {
		this.accessList = accessList;
    this.userList = userList;
	}

	void add(User user) {
		userList ~= user;
    user.id = userList.length - 1;
	}

  auto length() {
    return userList.length;
  }

	void empower(string email, string access) {
		auto user = this[email];

		enforce!UserAccesNotFoundException(accessList.canFind(access), "`" ~ access ~ "` it's not in the list");

		user.scopes ~= access;
	}

  User opIndex(string email) {
		auto list = userList.find!(a => a.email == email);

		enforce!UserNotFoundException(list.count > 0, "User not found");

		return list[0];
	}

  User opIndex(size_t index) {
    auto list = userList.find!(a => a.id == index);

		enforce!UserNotFoundException(list.count > 0, "User not found");

		return list[0];
	}

	User byToken(string token) {
		auto list = userList.find!(a => a.isValidToken(token));

		enforce!UserNotFoundException(list.count > 0, "User not found");

		return list[0];
	}

  auto opBinaryRight(string op)(string email) {
		static if (op == "in") {
			return !userList.filter!(a => a.email == email).empty;
		} else {
			static assert(false, op ~ " not implemented for `UserCollection`");
		}
	}

  auto opBinaryRight(string op)(long id) {
		static if (op == "in") {
			return !userList.filter!(a => a.id == id).empty;
		} else {
			static assert(false, op ~ " not implemented for `UserCollection`");
		}
	}

  int opApply(int delegate(ref User) dg) {
    int result = 0;

    foreach(user; userList) {
        result = dg(user);
        if (result)
          break;
    }

    return result;
  }

  @property User front() {
    return userList[index];
  }

  User moveFront() {
    index = 0;
    return front();
  }

  void popFront() {
    index++;
  }

  @property bool empty() {
    return index >= userList.length;
  }
}

unittest {
	auto collection = new UserCollection([]);
	auto user = new User("user", "password");

	collection.add(user);
	assert(collection["user"] == user, "It should return user by name");
	assert("user" in collection, "It should find user by name");
	assert("other user" !in collection, "It should not find user by name");

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
