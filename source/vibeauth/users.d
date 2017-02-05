module vibeauth.users;

import vibe.data.json;

import std.stdio;
import std.algorithm.searching;
import std.algorithm.iteration;
import std.exception;
import std.uuid;
import std.conv;
import std.datetime;
import std.array;

import vibeauth.collection;
import vibeauth.token;

version(unittest) import bdd.base;

alias UserNotFoundException = ItemNotFoundException;

class UserAccesNotFoundException : Exception {
	this(string msg = null, Throwable next = null) { super(msg, next); }
	this(string msg, string file, size_t line, Throwable next = null) {
		super(msg, file, line, next);
	}
}

struct UserData {
	string _id;

	string name;
	string username;
	string email;

	string password;
	string salt;

	bool isActive;

	string[] scopes;
	Token[] tokens;
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

	override string toString() {
		return toJson.toPrettyString;
	}

	@property {
		auto id() const {
			return userData._id;
		}

		void id(ulong value) {
			userData._id = value.to!string;

			if(onChange) {
				onChange(this);
			}
		}

		auto isActive() const {
			return userData.isActive;
		}

		void isActive(bool value) {
			userData.isActive = value;
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

		auto name() const {
			return userData.name;
		}

		void name(string value) {
			userData.name = value;

			if(onChange) {
				onChange(this);
			}
		}

		auto username() const {
			return userData.username;
		}

		void username(string value) {
			userData.username = value;

			if(onChange) {
				onChange(this);
			}
		}
	}

	void revoke(string token) {
		userData.tokens = userData.tokens.filter!(a => a.name != token).array;
	}

	const {
		string[] getScopes(string token) {
			return userData.tokens.filter!(a => a.name == token).front.scopes.to!(string[]);
		}

		bool can(string access)() {
			return userData.scopes.canFind(access);
		}

		auto getTokensByType(string type) {
			return userData.tokens.filter!(a => a.type == type);
		}

		bool isValidPassword(string password) {
			return sha1UUID(userData.salt ~ "." ~ password).to!string == userData.password;
		}

		bool isValidToken(string token) {
			return userData.tokens.map!(a => a.name).canFind(token);
		}

		bool isValidToken(string token, string requiredScope) {
			return userData.tokens.filter!(a => a.scopes.canFind(requiredScope)).map!(a => a.name).canFind(token);
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

	Token createToken(SysTime expire, string[] scopes = [], string type = "Bearer") {
		auto token = Token(randomUUID.to!string, expire, scopes, type);
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
		data["name"] = name;
		data["username"] = username;
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

abstract class UserCollection : Collection!User {

	alias opBinaryRight = Collection!User.opBinaryRight;
	alias opIndex = Collection!User.opIndex;

	this(User[] list = []) {
		super(list);
	}

	abstract {
		bool createUser(UserData data, string password);
		Token createToken(string email, SysTime expire, string[] scopes = [], string type = "Bearer");
		void revoke(string token);
		void empower(string email, string access);
		User byToken(string token);
		bool contains(string email);
	}
}

class UserMemmoryCollection : UserCollection {
	long index = 0;
	immutable(string[]) accessList;

	this(immutable(string[]) accessList, User[] list = []) {
		this.accessList = accessList;
		super(list);
	}

	override {
		bool createUser(UserData data, string password) {
			auto user = new User(data);
			user.setPassword(password);

			list ~= user;

			return true;
		}

		User opIndex(string identification) {
			auto result = list.find!(a => a.email == identification || a.username == identification);

			enforce!UserNotFoundException(result.count > 0, "User not found");

			return result[0];
		}

		Token createToken(string email, SysTime expire, string[] scopes = [], string type = "Bearer") {
			return opIndex(email).createToken(expire, scopes, type);
		}

		void revoke(string token) {
			byToken(token).revoke(token);
		}

		void empower(string email, string access) {
			auto user = this[email];

			enforce!UserAccesNotFoundException(accessList.canFind(access), "`" ~ access ~ "` it's not in the list");

			user.addScope(access);
		}

		User byToken(string token) {
			auto result = list.find!(a => a.isValidToken(token));

			enforce!UserNotFoundException(result.count > 0, "User not found");

			return result[0];
		}

		bool contains(string identification) {
			return !list.filter!(a => a.email == identification || a.username == identification).empty;
		}
	}
}

unittest {
	auto collection = new UserMemmoryCollection([]);
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
	assert("name" in json, "It should contain the name");
	assert("username" in json, "It should contain the username");
	assert("email" in json, "It should contain the email");
	assert("password" !in json, "It should not contain the password");
	assert("salt" !in json, "It should not contain the salt");
	assert("scopes" in json, "It should contain the scope");
	assert("tokens" !in json, "It should not contain the tokens");
}

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

unittest {
	auto collection = new UserMemmoryCollection(["doStuff"]);
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
	auto collection = new UserMemmoryCollection([]);
	auto user = new User("user", "password");

	collection.add(user);
	auto token = user.createToken(Clock.currTime + 3600.seconds);

	assert(collection.byToken(token.name) == user, "It should find user by token");

	bool thwrown;

	try {
		collection.byToken("token");
	} catch (Exception e) {
		thwrown = true;
	}

	assert(thwrown, "It should raise exception when an user it's not found by token");
}

@("Token revoke")
unittest {
	auto collection = new UserMemmoryCollection([]);
	auto user = new User("user", "password");

	collection.add(user);
	auto token = user.createToken(Clock.currTime + 3600.seconds);

	assert(collection.byToken(token.name) == user, "It should find user by token");

	collection.revoke(token.name);

	should.throwAnyException({
		collection.byToken(token.name);
	});
}

@("Get tokens by type")
unittest {
	auto collection = new UserMemmoryCollection([]);
	auto user = new User("user", "password");

	collection.add(user);
	auto token = user.createToken(Clock.currTime + 3600.seconds, [], "activation");
	auto tokens = collection["user"].getTokensByType("activation").array;

	tokens.length.should.equal(1);
	tokens.should.contain(token);
}

@("Remove user by id")
unittest {
	auto collection = new UserMemmoryCollection([]);
	auto user = new User("user", "password");
	user.id = 1;

	collection.add(user);
	collection.remove("1");

	assert(collection.length == 0, "It should remove user by id");
}
