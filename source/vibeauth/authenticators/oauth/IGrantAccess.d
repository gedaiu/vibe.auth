module vibeauth.authenticators.oauth.IGrantAccess;

import vibeauth.authenticators.oauth.AuthData;
import vibeauth.collections.usercollection;

import vibe.data.json;

///
interface IGrantAccess {
  /// setter for the authentication data
  void authData(AuthData authData);

  /// setter for the user collection
  void userCollection(UserCollection userCollection);

  /// validate the auth data
  bool isValid();

  /// get a Json response
  Json get();
}
