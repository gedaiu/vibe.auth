/++
  A module that defines the user model

  Copyright: © 2018-2020 Szabo Bogdan
  License: Subject to the terms of the MIT license, as written in the included LICENSE.txt file.
  Authors: Szabo Bogdan
+/

module vibeauth.data.usermodel;

import vibeauth.data.token;
import vibe.data.json : optional;

/// User data used to manage an user
struct UserModel {
  /// The user id
  string _id;

  ///
  string name;

  ///
  string username;

  /// The users email
  string email;

  /// The password hash
  string password;

  /// String concatenated with the pasword before hashing
  string salt;

  /// Flag used to determine if the user can perform any actions
  bool isActive;

  /// The timestamp of the users last activity
  @optional ulong lastActivity;

  /// Scopes that the user has access to
  string[] scopes;

  /// A list of active tokens
  Token[] tokens;
}
