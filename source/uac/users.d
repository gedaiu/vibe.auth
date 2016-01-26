module vibeauth.users;

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
	size_t id;
	string email;

	string password;
	string salt;

	string token;

	string[] rights;
	string[] tokens;

  this() { }

	this(string email, string password) {
		this.email = email;
		this.salt = randomUUID.to!string;
		this.password = sha1UUID(salt ~ "." ~ password).to!string;
	}

	const {
		bool can(string access)() {
			return rights.canFind(access);
		}

		bool isValidPassword(string password) {
			return sha1UUID(salt ~ "." ~ password).to!string == this.password;
		}

		bool isValidToken(string token) {
			return tokens.canFind(token);
		}
	}

	string createToken() {
		auto token = randomUUID.to!string;
		tokens ~= token;

		return token;
	}
}

class UserCollection {
	immutable(string[]) accessList;

	private User[] userList;

	this(immutable(string[]) accessList, User[] userList = []) {
		this.accessList = accessList;
    this.userList = userList;
	}

	void add(User user) {
		userList ~= user;
	}

  auto length() {
    return userList.length;
  }

	void empower(string name, string access) {
		auto user = this[name];

		enforce!UserAccesNotFoundException(accessList.canFind(access), "`" ~ access ~ "` it's not in the list");

		user.rights ~= access;
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
