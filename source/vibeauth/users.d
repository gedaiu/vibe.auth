/++
  A module containing the user handling logic

  Copyright: © 2018-2020 Szabo Bogdan
  License: Subject to the terms of the MIT license, as written in the included LICENSE.txt file.
  Authors: Szabo Bogdan
+/
module vibeauth.users;

import vibe.data.json;

version(unittest) import fluent.asserts;

private import vibeauth.data.usermodel;
private import vibeauth.error;

deprecated("use vibeauth.data.usermodel.UserModel instead") alias UserData = vibeauth.data.usermodel.UserModel;
deprecated("use vibeauth.data.user instead") alias User = vibeauth.data.user.User;
deprecated("use vibeauth.error.UserNotFoundException instead") alias UserNotFoundException = vibeauth.error.UserNotFoundException;
deprecated("use vibeauth.error.UserAccesNotFoundException instead") alias UserAccesNotFoundException = vibeauth.error.UserAccesNotFoundException;
deprecated("use vibeauth.error.ItemNotFoundException instead") alias ItemNotFoundException = vibeauth.error.ItemNotFoundException;

import vibeauth.collections.usercollection;
deprecated("use vibeauth.collections.usercollection.UserCollection instead") alias UserCollection = vibeauth.collections.usercollection.UserCollection;

import vibeauth.collections.usermemory;
deprecated("use vibeauth.collections.usermemory.UserMemoryCollection instead") alias UserMemmoryCollection = vibeauth.collections.usermemory.UserMemoryCollection;
