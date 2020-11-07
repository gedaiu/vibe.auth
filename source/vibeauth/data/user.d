/++
  A module containing a class that handles users data

  Copyright: © 2018-2020 Szabo Bogdan
  License: Subject to the terms of the MIT license, as written in the included LICENSE.txt file.
  Authors: Szabo Bogdan
+/

module vibeauth.data.user;

import vibeauth.data.usermodel;
import vibeauth.data.token;

import std.datetime;
import std.conv;
import std.algorithm;
import std.uuid;
import std.array;

import vibe.crypto.cryptorand;

import vibe.data.json;

/// Class used to manage one user
class User {

  /// Event type raised when the user data has changed
  alias ChangedEvent = void delegate(User);

  /// Event raised when the user changed
  ChangedEvent onChange;

  private {
    UserModel userData;
  }

  ///
  this() { }

  ///
  this(UserModel userData) {
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
      userData.lastActivity = Clock.currTime.toUnixTime!long;

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
      userData.lastActivity = Clock.currTime.toUnixTime!long;

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
      userData.lastActivity = Clock.currTime.toUnixTime!long;

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
      userData.lastActivity = Clock.currTime.toUnixTime!long;

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
      userData.lastActivity = Clock.currTime.toUnixTime!long;

      if(onChange) {
        onChange(this);
      }
    }

    /// Get the last user activity timestamp
    auto lastActivity() const {
      return userData.lastActivity;
    }

    /// Set the last user activity timestam[]
    void lastActivity(ulong value) {
      userData.lastActivity = value;

      if(onChange) {
        onChange(this);
      }
    }
  }

  /// Revoke a token
  void revoke(string token) {
    userData.tokens = userData.tokens.filter!(a => a.name != token).array;
    userData.lastActivity = Clock.currTime.toUnixTime!long;

    if(onChange) {
      onChange(this);
    }
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
      auto now = Clock.currTime;
      return userData.tokens.filter!(a => a.type == type && a.expire > now);
    }

    /// Validate a password
    bool isValidPassword(string password) {
      return sha1UUID(userData.salt ~ "." ~ password).to!string == userData.password;
    }

    /// Validate a token
    bool isValidToken(string token) {
      auto now = Clock.currTime;
      return userData.tokens.filter!(a => a.expire > now).map!(a => a.name).canFind(token);
    }

    /// Validate a token against a scope
    bool isValidToken(string token, string requiredScope) {
      auto now = Clock.currTime;
      return userData.tokens.filter!(a => a.scopes.canFind(requiredScope) && a.expire > now).map!(a => a.name).canFind(token);
    }
  }

  void removeExpiredTokens() {
    auto now = Clock.currTime;
    auto newTokenList = userData.tokens.filter!(a => a.expire > now).array;

    if(newTokenList.length != userData.tokens.length) {
      userData.tokens = newTokenList;

      if(onChange) {
        onChange(this);
      }
    }
  }

  /// Change the user password
  void setPassword(string password) {
    ubyte[16] secret;
    secureRNG.read(secret[]);
    auto uuid = UUID(secret);

    userData.salt = uuid.to!string;
    userData.password = sha1UUID(userData.salt ~ "." ~ password).to!string;
    userData.lastActivity = Clock.currTime.toUnixTime!long;

    if(onChange) {
      onChange(this);
    }
  }

  /// Change the user password by providing a salting string
  void setPassword(string password, string salt) {
    userData.salt = salt;
    userData.password = password;
    userData.lastActivity = Clock.currTime.toUnixTime!long;

    if(onChange) {
      onChange(this);
    }
  }

  /// Add a scope to the user
  void addScope(string access) {
    userData.scopes ~= access;
    userData.lastActivity = Clock.currTime.toUnixTime!long;

    if(onChange) {
      onChange(this);
    }
  }

  /// Remove a scope from user
  void removeScope(string access) {
    userData.scopes = userData.scopes
      .filter!(a => a != access).array;
    userData.lastActivity = Clock.currTime.toUnixTime!long;

    if(onChange) {
      onChange(this);
    }
  }

  /// Create an user token
  Token createToken(SysTime expire, string[] scopes = [], string type = "Bearer", string[string] meta = null) {
    ubyte[16] secret;
    secureRNG.read(secret[]);
    auto uuid = UUID(secret);

    auto token = Token(uuid.to!string, expire, scopes, type, meta);
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
    return new User(data.deserializeJson!UserModel);
  }
}
