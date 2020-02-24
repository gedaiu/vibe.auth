/++
  A module containing a structure that stores user data in memory

  Copyright: © 2018-2020 Szabo Bogdan
  License: Subject to the terms of the MIT license, as written in the included LICENSE.txt file.
  Authors: Szabo Bogdan
+/

module vibeauth.collections.usermemory;

import vibeauth.collections.usercollection;
import vibeauth.data.usermodel;
import vibeauth.data.token;
import vibeauth.data.user;
import vibeauth.error;

import std.datetime;
import std.algorithm;
import std.exception;
import std.range;

/// Create an user collection stored in memmory
class UserMemoryCollection : UserCollection {
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
    bool createUser(UserModel data, string password) {
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
    Token createToken(string email, SysTime expire, string[] scopes = [], string type = "Bearer", string[string] meta = null) {
      return opIndex(email).createToken(expire, scopes, type, meta);
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