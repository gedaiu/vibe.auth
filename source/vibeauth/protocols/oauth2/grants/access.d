module vibeauth.protocols.oauth2.grants.access;

import vibeauth.protocols.oauth2.authdata;
import vibeauth.identity.usercollection;

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
