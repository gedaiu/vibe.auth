/++
  A module that defines the user model

  Copyright: © 2018-2020 Szabo Bogdan
  License: Subject to the terms of the MIT license, as written in the included LICENSE.txt file.
  Authors: Szabo Bogdan
+/

module vibeauth.identity.usermodel;

import vibeauth.identity.token;
import vibe.data.json : optional;
import std.datetime;

/// User data used to manage an user
struct UserModel {
  /// The user id
  string _id;

  @optional {
    /// The users salutation eg. mr/ms or unset
    string salutation;

    /// The users title eg. dr
    string title;

    /// The users first name
    string firstName;

    /// The users last name
    string lastName;
  }

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

  ///
  @optional SysTime createdAt;

  /// The timestamp of the users last activity
  @optional ulong lastActivity;

  /// Scopes that the user has access to
  string[] scopes;

  /// A list of active tokens
  Token[] tokens;

  string name() {
    return this.firstName ~ " " ~ this.lastName;
  }

  void name(string) {}
}

version(unittest) {
  import fluent.asserts;
}

@("name returns firstName concatenated with lastName")
unittest {
  UserModel m;
  m.firstName = "John";
  m.lastName = "Doe";

  m.name.should.equal("John Doe");
}

@("name returns space when names are empty")
unittest {
  UserModel m;
  m.name.should.equal(" ");
}

@("default field values are empty")
unittest {
  UserModel m;

  m._id.should.equal("");
  m.email.should.equal("");
  m.password.should.equal("");
  m.salt.should.equal("");
  m.isActive.should.equal(false);
  m.scopes.length.should.equal(0);
  m.tokens.length.should.equal(0);
}
