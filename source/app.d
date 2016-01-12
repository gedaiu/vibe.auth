module uac;

import std.stdio;
import std.algorithm.searching;
import std.exception;
import std.uuid;
import std.conv;

class UserNotFoundException : Exception {
  this(string msg = null, Throwable next = null) { super(msg, next); }
  this(string msg, string file, size_t line, Throwable next = null) {
    super(msg, file, line, next);
  }
}

class User {
	string id;

	string name;

	string password;
	string salt;

	string token;
	string key;

	string[] rights;

	this(string name, string password) {
		this.name = name;
		this.salt = randomUUID.to!string;
		this.password = sha1UUID(salt ~ "." ~ password).to!string;
	}
}

class UserCollection {
	immutable(string[]) accessList;

	private User[] userList;

	void add(User user) {
		userList ~= user;
	}

	User opIndex(string name) {
		auto list = userList.find!(a => a.name = name);

		enforce!UserNotFoundException(list.count > 0, "User not found");

		return list[0];
	}
}

unittest {
	auto collection = new UserCollection();

	auto user = new User("user", "password");

	collection.add(user);
	assert(collection["user"] == user);
}

unittest {
	auto user = new User("user", "password");
	assert(user.password == sha1UUID(user.salt ~ ".password").to!string);
}

void main() {}
