/++
  A module containing a generic class to handle users

  Copyright: © 2018-2020 Szabo Bogdan
  License: Subject to the terms of the MIT license, as written in the included LICENSE.txt file.
  Authors: Szabo Bogdan
+/


module vibeauth.collections.usercollection;

import std.datetime;

import vibeauth.collections.base;
import vibeauth.data.usermodel;
import vibeauth.data.token;
import vibeauth.data.user;

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
    bool createUser(UserModel data, string password);

    /// Create a token for an user
    Token createToken(string email, SysTime expire, string[] scopes = [], string type = "Bearer", string[string] meta = null);

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