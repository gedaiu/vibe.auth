/++
  A module containing the user handling logic

  Copyright: © 2018 Szabo Bogdan
  License: Subject to the terms of the MIT license, as written in the included LICENSE.txt file.
  Authors: Szabo Bogdan
+/
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

version(unittest) import fluent.asserts;

/// Exception thrown when an user does not exist
alias UserNotFoundException = ItemNotFoundException;

/// Exception thrown when an access level does not exist
class UserAccesNotFoundException : Exception {

  /// Create the exception
  this(string msg = null, Throwable next = null) { super(msg, next); }

  /// dutto
  this(string msg, string file, size_t line, Throwable next = null) {
    super(msg, file, line, next);
  }
}

/// User data used to manage an user
struct UserData {
  /// The user id
  string _id;

  ///
  string name;

  ///
  string username;
  
  ///
  string email;

  ///
  string password;
  
  /// 
  string salt;

  /// Flag used to determine if the user can perform any actions
  bool isActive;

  /// Scopes that the user has access to
  string[] scopes;

  /// A list of active tokens
  Token[] tokens;
}

/// Class used to manage one user
class User {

  /// Event type raised when the user data has changed
  alias ChangedEvent = void delegate(User);

  /// Event raised when the user changed
  ChangedEvent onChange;

  private {
    UserData userData;
  }

  ///
  this() { }

  ///
  this(UserData userData) {
    this.userData = userData;
  }
 
  /// 
  this(string email, string password) {
    this.userData.email = email;
    setPassword(password);
  }

  /// Convert the user object ot a Json pretty string
  override string toString() {
    return toJson.toPrettyString;
  }

  @property {
    /// Get the user id
    auto id() const {
      return userData._id;
    }

    /// Set the user id
    void id(ulong value) {
      userData._id = value.to!string;

      if(onChange) {
        onChange(this);
      }
    }

    /// Check if the user is active
    bool isActive() const {
      return userData.isActive;
    }

    /// Check the user active status
    void isActive(bool value) {
      userData.isActive = value;

      if(onChange) {
        onChange(this);
      }
    }

    /// Get the user email
    string email() const {
      return userData.email;
    }

    /// Set the user email
    void email(string value) {
      userData.email = value;

      if(onChange) {
        onChange(this);
      }
    }

    /// Get the user real name
    auto name() const {
      return userData.name;
    }

    /// Set the user real name
    void name(string value) {
      userData.name = value;

      if(onChange) {
        onChange(this);
      }
    }

    /// Get the user alias name
    auto username() const {
      return userData.username;
    }

    /// Set the user alias name
    void username(string value) {
      userData.username = value;

      if(onChange) {
        onChange(this);
      }
    }
  }

  /// Revoke a token
  void revoke(string token) {
    userData.tokens = userData.tokens.filter!(a => a.name != token).array;
  }

  const {
    /// Get the user scopes assigned to a particullar token
    string[] getScopes(string token) {
      return userData.tokens.filter!(a => a.name == token).front.scopes.to!(string[]);
    }

    /// Get all user scopes
    string[] getScopes() {
      return userData.scopes.dup;
    }

    /// Check if an user can access a scope
    bool can(string access)() {
      return userData.scopes.canFind(access);
    }

    /// Get a range of tokens of a certain type
    auto getTokensByType(string type) {
      return userData.tokens.filter!(a => a.type == type);
    }

    /// Validate a password
    bool isValidPassword(string password) {
      return sha1UUID(userData.salt ~ "." ~ password).to!string == userData.password;
    }

    /// Validate a token
    bool isValidToken(string token) {
      return userData.tokens.map!(a => a.name).canFind(token);
    }

    /// Validate a token against a scope
    bool isValidToken(string token, string requiredScope) {
      return userData.tokens.filter!(a => a.scopes.canFind(requiredScope)).map!(a => a.name).canFind(token);
    }
  }

  /// Change the user password
  void setPassword(string password) {
    userData.salt = randomUUID.to!string;
    userData.password = sha1UUID(userData.salt ~ "." ~ password).to!string;

    if(onChange) {
      onChange(this);
    }
  }

  /// Change the user password by providing a salting string
  void setPassword(string password, string salt) {
    userData.salt = salt;
    userData.password = password;

    if(onChange) {
      onChange(this);
    }
  }

  /// Add a scope to the user
  void addScope(string access) {
    userData.scopes ~= access;

    if(onChange) {
      onChange(this);
    }
  }

  /// Create an user token
  Token createToken(SysTime expire, string[] scopes = [], string type = "Bearer") {
    auto token = Token(randomUUID.to!string, expire, scopes, type);
    userData.tokens ~= token;

    if(onChange) {
      onChange(this);
    }

    return token;
  }

  /// Convert the object to a json. It's not safe to share this value
  /// with the outside world. Use it to store the user to db.
  Json toJson() const {
    return userData.serializeToJson;
  }

  /// Convert the object to a json that can be shared with the outside world
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

  /// Restore the user from a json value
  static User fromJson(Json data) {
    return new User(data.deserializeJson!UserData);
  }
}

/// Password validation
unittest {
  auto user = new User("user", "password");
  auto password = user.toJson["password"].to!string;
  auto salt = user.toJson["salt"].to!string;

  assert(password == sha1UUID(salt ~ ".password").to!string, "It should salt the password");
  assert(user.isValidPassword("password"), "It should return true for a valid password");
  assert(!user.isValidPassword("other passowrd"), "It should return false for an invalid password");
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

/// Collection used to manage user objects
abstract class UserCollection : Collection!User {
  ///
  alias opBinaryRight = Collection!User.opBinaryRight;

  ///
  alias opIndex = Collection!User.opIndex;

  /// Initialize the collection
  this(User[] list = []) {
    super(list);
  }

  abstract {
    /// Create a new user data from some user data
    bool createUser(UserData data, string password);

    /// Create a token for an user
    Token createToken(string email, SysTime expire, string[] scopes = [], string type = "Bearer");
    
    /// Revoke a token
    void revoke(string token);

    /// Empower an user with some scope access
    void empower(string email, string access);

    /// Get an user by an existing token
    User byToken(string token);

    /// Get an user by id
    User byId(string id);

    /// Check if the collection has an user by email
    bool contains(string email);
  }
}

/// Create an user collection stored in memmory
class UserMemmoryCollection : UserCollection {
  private {
    long index = 0;
    immutable(string[]) accessList;
  }

  ///
  this(immutable(string[]) accessList, User[] list = []) {
    this.accessList = accessList;
    super(list);
  }

  override {
    /// Create a new user data from some user data
    bool createUser(UserData data, string password) {
      auto user = new User(data);
      user.setPassword(password);

      list ~= user;

      return true;
    }

    /// Get an user by email or username
    User opIndex(string identification) {
      auto result = list.find!(a => a.email == identification || a.username == identification);

      enforce!UserNotFoundException(result.count > 0, "User not found");

      return result[0];
    }

    /// Create a token for an user
    Token createToken(string email, SysTime expire, string[] scopes = [], string type = "Bearer") {
      return opIndex(email).createToken(expire, scopes, type);
    }

    /// Revoke a token
    void revoke(string token) {
      byToken(token).revoke(token);
    }

    /// Empower an user with some scope access
    void empower(string email, string access) {
      auto user = this[email];

      enforce!UserAccesNotFoundException(accessList.canFind(access), "`" ~ access ~ "` it's not in the list");

      user.addScope(access);
    }

    /// Get an user by an existing token
    User byToken(string token) {
      auto result = list.find!(a => a.isValidToken(token));

      enforce!UserNotFoundException(!result.empty, "User not found");

      return result.front;
    }

    /// Get an user by id
    User byId(string id) {
      auto result = list.find!(a => a.id == id);

      enforce!UserNotFoundException(!result.empty, "User not found");

      return result.front;
    }

    /// Check if the collection has an user by email or username
    bool contains(string identification) {
      return !list.filter!(a => a.email == identification || a.username == identification).empty;
    }
  }
}

/// Throw exceptions on selecting invalid users
unittest {
  auto collection = new UserMemmoryCollection([]);
  auto user = new User("user", "password");

  collection.add(user);
  assert(collection["user"] == user, "It should return user by name");
  assert(collection.contains("user"), "It should find user by name");
  assert(!collection.contains("other user"), "It should not find user by name");

  ({
    collection["other user"];
  }).should.throwAnyException;
}

/// User access
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

/// Searching for a missing token
unittest {
  auto collection = new UserMemmoryCollection([]);
  auto user = new User("user", "password");

  collection.add(user);
  auto token = user.createToken(Clock.currTime + 3600.seconds);

  collection.byToken(token.name).name.should.equal(user.name).because("It should find user by token");

  ({
    collection.byToken("token");
  }).should.throwAnyException;
}

/// Token revoke
unittest {
  auto collection = new UserMemmoryCollection([]);
  auto user = new User("user", "password");

  collection.add(user);
  auto token = user.createToken(Clock.currTime + 3600.seconds);

  assert(collection.byToken(token.name) == user, "It should find user by token");

  collection.revoke(token.name);

  ({
    collection.byToken(token.name);
  }).should.throwAnyException;
}

/// Get tokens by type
unittest {
  auto collection = new UserMemmoryCollection([]);
  auto user = new User("user", "password");

  collection.add(user);
  auto token = user.createToken(Clock.currTime + 3600.seconds, [], "activation").name;
  auto tokens = collection["user"].getTokensByType("activation").map!(a => a.name).array;

  tokens.length.should.equal(1);
  tokens.should.contain(token);
}

/// Get user by id
unittest {
  auto collection = new UserMemmoryCollection([]);
  auto user = new User("user", "password");
  user.id = 1;

  collection.add(user);
  auto result = collection.byId("1");

  result.id.should.equal("1");
}

/// Remove user by id
unittest {
  bool wasRemoved;

  void onRemove(User user) {
    wasRemoved = user.id == "1";
  }

  auto collection = new UserMemmoryCollection([]);
  collection.onRemove = &onRemove;

  auto user = new User("user", "password");
  user.id = 1;

  collection.add(user);
  collection.remove("1");

  collection.length.should.equal(0);
  wasRemoved.should.equal(true);
}
