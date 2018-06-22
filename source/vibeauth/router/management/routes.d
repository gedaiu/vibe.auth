/++
  A module that handles the user management. It binds the routes, renders the templates and 
  updates the collections.

  Copyright: © 2018 Szabo Bogdan
  License: Subject to the terms of the MIT license, as written in the included LICENSE.txt file.
  Authors: Szabo Bogdan
+/
module vibeauth.router.management.routes;

import vibe.http.router;
import vibe.data.json;

import vibeauth.users;  
import vibeauth.collection;
import vibeauth.configuration;
import vibeauth.mail.base;
import vibeauth.router.management.responses;
import vibeauth.templatedata;
import vibeauth.templatedata;

import std.string;
import std.algorithm;
import std.conv;
import std.regex;

/// It handles vibe.d requests
class UserManagementRoutes {
  private {
    UserCollection userCollection;
    ServiceConfiguration configuration;

    IMailQueue mailQueue;

    IController[] controllers;
  }

  /// Initalize the object
  this(UserCollection userCollection, IMailQueue mailQueue, ServiceConfiguration configuration = ServiceConfiguration.init) {
    this.configuration = configuration;
    this.userCollection = userCollection;
    this.mailQueue = mailQueue;

    controllers = cast(IController[]) [
      new ListController(userCollection, configuration),

      new ProfileController(userCollection, configuration),
      new UpdateProfileController(userCollection, configuration),

      new AccountController(userCollection, configuration),
      new UpdateAccountController(userCollection, configuration),

      new DeleteAccountController(userCollection, configuration),

      new SecurityController(userCollection, configuration),
      new RevokeAdminController(userCollection, configuration),
      new MakeAdminController(userCollection, configuration)
    ];
  }

  /// Generic handler for all user management routes
  void handler(HTTPServerRequest req, HTTPServerResponse res) {
    foreach(controller; controllers) {
      if(controller.canHandle(req)) {
        controller.handle(req, res);
        return;
      }
    }
  }
}

string replaceConfiguration(T)(string data, T configuration, string path, string reqPath) {
  auto id = getId(configuration.paths.account, reqPath);

  auto jsonConfiguration = configuration.serializeToJson;
  jsonConfiguration["paths"].replaceId(id);

  return data.replaceVariables(jsonConfiguration);
}

void replaceId(ref Json data, string id) {
  foreach(ref string key, ref val; data) {
    data[key] = val.to!string.replace(":id", id);
  }
}

version(unittest) {
  import std.array;
  import std.datetime;
  import std.uri;

  import fluentasserts.vibe.request;
  import fluentasserts.vibe.json;
  import fluent.asserts;
  import vibeauth.token;

  UserMemmoryCollection collection;
  User user;
  TestMailQueue mailQueue;
  Token activationToken;
  Token authToken;
  UserManagementRoutes userManagement;

  alias MailMessage = vibeauth.mail.base.Message;

  class TestMailQueue : MailQueue
  {
    MailMessage[] messages;

    this() {
      super(EmailConfiguration());
    }

    override void addMessage(MailMessage message) {
      messages ~= message;
    }
  }

  auto testRouter() {
    auto router = new URLRouter();
    mailQueue = new TestMailQueue;

    collection = new UserMemmoryCollection(["doStuff", "admin"]);
    user = new User("user@gmail.com", "password");
    user.name = "John Doe";
    user.username = "test";
    user.id = 1;

    collection.add(user);
    activationToken = collection.createToken(user.email, Clock.currTime + 3600.seconds, [], "activation");
    authToken = collection.createToken(user.email, Clock.currTime + 3600.seconds, [], "webLogin");

    userManagement = new UserManagementRoutes(collection, mailQueue);

    router.any("*", &userManagement.handler);
    return router;
  }
}

/// It should render the user list
unittest {
  auto router = testRouter;
  collection.empower("user@gmail.com", "admin");
  
  router
    .request
    .get("/admin/users")
    .header("Cookie", "auth-token=" ~ authToken.name)
    .expectStatusCode(200)
    .end((Response response) => {
      response.bodyString.should.contain("user@gmail.com");
    });
}

/// It should render 404 when the user does not exist
unittest {
  auto router = testRouter;
  collection.empower("user@gmail.com", "admin");

  router
    .request
    .get("/admin/users/3")
    .expectStatusCode(404)
    .end();
}

/// It should update the user data
unittest {
  testRouter
    .request
    .post("/admin/users/1/update")
    .header("Cookie", "auth-token=" ~ authToken.name)
    .send(["name": " some name ", "username": " some-user-name "])
    .expectStatusCode(302)
    .expectHeader("Location", "http://localhost:0/admin/users/1?message=Profile%20updated%20successfully.")
    .end((Response response) => {
      auto user = collection.byId("1");
      user.name.should.equal("some name");
      user.username.should.equal("some-user-name");
    });
}

/// It should not be able to update the username to an existing one
unittest {
  auto router = testRouter;
  collection.empower("user@gmail.com", "admin");

  auto user = new User("user2@gmail.com", "password");
  user.name = "John Doe";
  user.username = "other test";
  user.id = 2;

  collection.add(user);

  router
    .request
    .post("/admin/users/2/update")
    .header("Cookie", "auth-token=" ~ authToken.name)
    .send(["name": " some name ", "username": "test"])
    .expectStatusCode(302)
    .expectHeader("Location", "http://localhost:0/admin/users/2?error=The%20new%20username%20is%20already%20taken.")
    .end((Response response) => {
      auto user = collection.byId("2");
      user.name.should.equal("John Doe");
      user.username.should.equal("other test");
    });
}

/// It should not update the user data when the name is missing
unittest {
  testRouter
    .request
    .post("/admin/users/1/update")
    .header("Cookie", "auth-token=" ~ authToken.name)
    .send(["username": "some user name"])
    .expectStatusCode(302)
    .expectHeader("Location", "http://localhost:0/admin/users/1?error=Missing%20data.%20The%20request%20can%20not%20be%20processed.")
    .end((Response response) => {
      auto user = collection.byId("1");
      user.name.should.equal("John Doe");
      user.username.should.equal("test");
    });
}

/// It should not update the user data when the name is missing
unittest {
  testRouter
    .request
    .post("/admin/users/1/update")
    .header("Cookie", "auth-token=" ~ authToken.name)
    .send(["name": "name"])
    .expectStatusCode(302)
    .expectHeader("Location", "http://localhost:0/admin/users/1?error=Missing%20data.%20The%20request%20can%20not%20be%20processed.")
    .end((Response response) => {
      auto user = collection.byId("1");
      user.name.should.equal("John Doe");
      user.username.should.equal("test");
    });
}

/// It should not update the user data when the username is empty
unittest {
  testRouter
    .request
    .post("/admin/users/1/update")
    .header("Cookie", "auth-token=" ~ authToken.name)
    .send(["name": "", "username": ""])
    .expectStatusCode(302)
    .expectHeader("Location", "http://localhost:0/admin/users/1?error=The%20username%20is%20mandatory.")
    .end((Response response) => {
      auto user = collection.byId("1");
      user.name.should.equal("John Doe");
      user.username.should.equal("test");
    });
}

/// It should escape the user data inputs
unittest {
  testRouter
    .request
    .post("/admin/users/1/update")
    .header("Cookie", "auth-token=" ~ authToken.name)
    .send(["name": "\"'<>", "username": "Asd"])
    .expectStatusCode(302)
    .expectHeader("Location", "http://localhost:0/admin/users/1?message=Profile%20updated%20successfully.")
    .end((Response response) => {
      auto user = collection.byId("1");
      user.name.should.equal("&quot;&#039;&lt;&gt;");
    });
}

/// It should change the user password
unittest {
  testRouter
    .request
    .post("/admin/users/1/account/update")
    .header("Cookie", "auth-token=" ~ authToken.name)
    .send(["oldPassword": "password", "newPassword": "new-password", "confirmPassword": "new-password"])
    .expectStatusCode(302)
    .expectHeader("Location", "http://localhost:0/admin/users/1/account?message=Password%20updated%20successfully.")
    .end((Response response) => {
      collection.byId("1").isValidPassword("new-password").should.equal(true);
    });
}

/// It should not change the user password when the old is not valid
unittest {
  testRouter
    .request
    .post("/admin/users/1/account/update")
    .header("Cookie", "auth-token=" ~ authToken.name)
    .send(["oldPassword": "wrong password", "newPassword": "new-password", "confirmPassword": "new-password"])
    .expectStatusCode(302)
    .expectHeader("Location", "http://localhost:0/admin/users/1/account?error=The%20old%20password%20is%20not%20valid.")
    .end((Response response) => {
      collection.byId("1").isValidPassword("password").should.equal(true);
    });
}

/// It should not change the user password when newPassword does not match confirmation
unittest {
  testRouter
    .request
    .post("/admin/users/1/account/update")
    .header("Cookie", "auth-token=" ~ authToken.name)
    .send(["oldPassword": "password", "newPassword": "new-password", "confirmPassword": "some-password"])
    .expectStatusCode(302)
    .expectHeader("Location", "http://localhost:0/admin/users/1/account?error=Password%20confirmation%20doesn't%20match%20the%20password.")
    .end((Response response) => {
      collection.byId("1").isValidPassword("password").should.equal(true);
    });
}

/// It should not change the user password when there are missing form data
unittest {
  testRouter
    .request
    .post("/admin/users/1/account/update")
    .header("Cookie", "auth-token=" ~ authToken.name)
    .send(["":""])
    .expectStatusCode(302)
    .expectHeader("Location", "http://localhost:0/admin/users/1/account?error=oldPassword%20newPassword%20confirmPassword%20fields%20are%20missing.")
    .end((Response response) => {
      collection.byId("1").isValidPassword("password").should.equal(true);
    });
}

/// It should not change the user password when newPassword is less than 10 chars
unittest {
  testRouter
    .request
    .post("/admin/users/1/account/update")
    .header("Cookie", "auth-token=" ~ authToken.name)
    .send(["oldPassword": "password", "newPassword": "new", "confirmPassword": "new"])
    .expectStatusCode(302)
    .expectHeader("Location", "http://localhost:0/admin/users/1/account?error=The%20new%20password%20is%20less%20then%2010%20chars.")
    .end((Response response) => {
      collection.byId("1").isValidPassword("password").should.equal(true);
    });
}

/// It should remove an user
unittest {
  testRouter
    .request
    .post("/admin/users/1/delete")
    .header("Cookie", "auth-token=" ~ authToken.name)
    .send(["password": "password"])
    .expectStatusCode(302)
    .expectHeader("Location", "http://localhost")
    .end((Response response) => {
      collection.contains("user@gmail.com").should.equal(false);
    });
}

/// It should not remove an user if the password is invalid
unittest {
  testRouter
    .request
    .post("/admin/users/1/delete")
    .header("Cookie", "auth-token=" ~ authToken.name)
    .send(["password": "invalid"])
    .expectStatusCode(302)
    .expectHeader("Location", "http://localhost:0/admin/users/1/account?error=Can%20not%20delete%20account.%20The%20password%20was%20invalid.")
    .end((Response response) => {
      collection.contains("user@gmail.com").should.equal(true);
    });
}

/// It should not remove an user if the password is missing
unittest {
  testRouter
    .request
    .post("/admin/users/1/delete")
    .header("Cookie", "auth-token=" ~ authToken.name)
    .send(["": "password"])
    .expectStatusCode(302)
    .expectHeader("Location", "http://localhost:0/admin/users/1/account?error=Can%20not%20delete%20account.%20The%20password%20was%20missing.")
    .end((Response response) => {
      collection.contains("user@gmail.com").should.equal(true);
    });
}

/// It should redirect to login on missing auth
unittest {
  auto paths = [
    "/admin/users",
    "/admin/users/1",
    "/admin/users/1/account",
    "/admin/users/1/delete",
    "/admin/users/1/security",
    "/admin/users/1/security/make-admin",
    "/admin/users/1/security/revoke-admin"
  ];

  foreach(path; paths) {
    testRouter
      .request
      .get(path)
      .expectStatusCode(302)
      .expectHeader("Location", "http://localhost:0/login")
      .end;
  }

  paths = [
    "/admin/users/1/update",
    "/admin/users/1/account/update",
    "/admin/users/1/delete",
    "/admin/users/1/security/make-admin",
    "/admin/users/1/security/revoke-admin"
  ];

  foreach(path; paths) {
    testRouter
      .request
      .post(path)
      .expectStatusCode(302)
      .expectHeader("Location", "http://localhost:0/login")
      .end;
  }
}

/// It should not access the other users profiles when the loged user is not admin
unittest {
  auto paths = [
    "/admin/users",
    "/admin/users/1",
    "/admin/users/1/account",
    "/admin/users/1/delete",
    "/admin/users/1/security",
    "/admin/users/1/security/make-admin",
    "/admin/users/1/security/revoke-admin"
  ];

  foreach(path; paths) {
    auto router = testRouter;

    auto otherUser = new User("bravo@gmail.com", "other-password");
    otherUser.name = "John Bravo";
    otherUser.username = "test2";
    otherUser.id = 2;
    collection.add(otherUser);
    authToken = collection.createToken(otherUser.email, Clock.currTime + 3600.seconds, [], "webLogin");

    router
      .request
      .get(path)
      .header("Cookie", "auth-token=" ~ authToken.name)
      .expectStatusCode(404)
      .end;
  }


  paths = [
    "/admin/users/1/update",
    "/admin/users/1/account/update",
    "/admin/users/1/delete",
    "/admin/users/1/security/make-admin",
    "/admin/users/1/security/revoke-admin"
  ];

  foreach(path; paths) {
    auto router = testRouter;

    auto otherUser = new User("bravo@gmail.com", "other-password");
    otherUser.name = "John Bravo";
    otherUser.username = "test2";
    otherUser.id = 2;
    collection.add(otherUser);
    authToken = collection.createToken(otherUser.email, Clock.currTime + 3600.seconds, [], "webLogin");

    router
      .request
      .post(path)
      .header("Cookie", "auth-token=" ~ authToken.name)
      .expectStatusCode(404)
      .end;
  }
}

/// On security page, it should not render rights section
/// if the loged user is not admin
unittest {
  testRouter
    .request
    .get("/admin/users/1/security")
    .header("Cookie", "auth-token=" ~ authToken.name)
    .end((Response response) => {
      response.bodyString.should.not.contain("You are");
      response.bodyString.should.not.contain("not an administrator");
      response.bodyString.should.not.contain("make admin");
      response.bodyString.should.not.contain("/1/security/make-admin");
    });
}

/// On security page, a loged user should not be able to revoke his own
/// admin rights
unittest {
  auto router = testRouter;
  collection.empower("user@gmail.com", "admin");

  router
    .request
    .get("/admin/users/1/security")
    .header("Cookie", "auth-token=" ~ authToken.name)
    .end((Response response) => {
      response.bodyString.should.contain("can not revoke");
      response.bodyString.should.contain("Ask another user");
      response.bodyString.should.not.contain("revoke admin");
      response.bodyString.should.not.contain("/1/security/revoke-admin");
    });
}

/// On security page, a loged admin should be make an user admin
unittest {
  auto router = testRouter;
  collection.empower("user@gmail.com", "admin");

  auto otherUser = new User("bravo@gmail.com", "password");
  otherUser.name = "John Bravo";
  otherUser.username = "test2";
  otherUser.id = 2;
  collection.add(otherUser);

  router
    .request
    .get("/admin/users/2/security")
    .header("Cookie", "auth-token=" ~ authToken.name)
    .end((Response response) => {
      response.bodyString.should.contain("This user is");
      response.bodyString.should.contain("not an administrator");
      response.bodyString.should.contain("make admin");
      response.bodyString.should.contain("/2/security/make-admin");
      response.bodyString.should.not.contain("revoke admin");
      response.bodyString.should.not.contain("/2/security/revoke-admin");
    });
}

/// On security page, a loged admin should be make an revoke admin rights
unittest {
  auto router = testRouter;
  collection.empower("user@gmail.com", "admin");

  auto otherUser = new User("bravo@gmail.com", "password");
  otherUser.name = "John Bravo";
  otherUser.username = "test2";
  otherUser.id = 2;
  collection.add(otherUser);
  collection.empower("bravo@gmail.com", "admin");

  router
    .request
    .get("/admin/users/2/security")
    .header("Cookie", "auth-token=" ~ authToken.name)
    .end((Response response) => {
      response.bodyString.should.contain("This user is");
      response.bodyString.should.not.contain("not an administrator");
      response.bodyString.should.contain("an administrator");
      response.bodyString.should.contain("revoke admin");
      response.bodyString.should.contain("/2/security/revoke-admin");
      response.bodyString.should.not.contain("make admin");
      response.bodyString.should.not.contain("/2/security/make-admin");
    });
}

/// The revoke admin question should have the right message
unittest {
  auto router = testRouter;
  collection.empower("user@gmail.com", "admin");

  auto otherUser = new User("bravo@gmail.com", "other-password");
  otherUser.name = "John Bravo";
  otherUser.username = "test2";
  otherUser.id = 2;
  collection.add(otherUser);
  collection.empower("bravo@gmail.com", "admin");

  router
    .request
    .get("/admin/users/2/security/revoke-admin")
    .header("Cookie", "auth-token=" ~ authToken.name)
    .end((Response response) => {
      response.bodyString.should.contain("Revoke admin");
      response.bodyString.should.contain("Are you sure you want to revoke the admin rights of this user?");
      response.bodyString.should.contain("Revoke");
      response.bodyString.should.contain("/2/security/revoke-admin");
    });
}

/// The revoke admin action should remove the admin rights
unittest {
  auto router = testRouter;
  collection.empower("user@gmail.com", "admin");

  auto otherUser = new User("bravo@gmail.com", "other-password");
  otherUser.name = "John Bravo";
  otherUser.username = "test2";
  otherUser.id = 2;
  collection.add(otherUser);
  collection.empower("bravo@gmail.com", "admin");

  router
    .request
    .post("/admin/users/2/security/revoke-admin")
    .header("Cookie", "auth-token=" ~ authToken.name)
    .send(["password": "password"])
    .expectStatusCode(302)
    .expectHeader("Location", "http://localhost:0/admin/users/2/security")
    .end((Response response) => {
      collection.byId("2").getScopes().should.not.contain("admin");
    });
}

/// The make admin question should have the right message
unittest {
  auto router = testRouter;
  collection.empower("user@gmail.com", "admin");

  auto otherUser = new User("bravo@gmail.com", "other-password");
  otherUser.name = "John Bravo";
  otherUser.username = "test2";
  otherUser.id = 2;
  collection.add(otherUser);

  router
    .request
    .get("/admin/users/2/security/make-admin")
    .header("Cookie", "auth-token=" ~ authToken.name)
    .end((Response response) => {
      response.bodyString.should.contain("Make admin");
      response.bodyString.should.contain("Are you sure you want to add admin rights to this user?");
      response.bodyString.should.contain("Make");
      response.bodyString.should.contain("/2/security/make-admin");
    });
}

/// The make admin action should add the admin rights
unittest {
  auto router = testRouter;
  collection.empower("user@gmail.com", "admin");

  auto otherUser = new User("bravo@gmail.com", "other-password");
  otherUser.name = "John Bravo";
  otherUser.username = "test2";
  otherUser.id = 2;
  collection.add(otherUser);

  router
    .request
    .post("/admin/users/2/security/make-admin")
    .header("Cookie", "auth-token=" ~ authToken.name)
    .send(["password": "password"])
    .expectStatusCode(302)
    .expectHeader("Location", "http://localhost:0/admin/users/2/security")
    .end((Response response) => {
      collection.byId("2").getScopes().should.contain("admin");
    });
}

/// The make admin action should not add the admin rights if the password is invalid
unittest {
  auto router = testRouter;
  collection.empower("user@gmail.com", "admin");

  auto otherUser = new User("bravo@gmail.com", "other-password");
  otherUser.name = "John Bravo";
  otherUser.username = "test2";
  otherUser.id = 2;
  collection.add(otherUser);

  router
    .request
    .post("/admin/users/2/security/make-admin")
    .header("Cookie", "auth-token=" ~ authToken.name)
    .send(["password": "other-password"])
    .expectStatusCode(302)
    .expectHeader("Location", "http://localhost:0/admin/users/2/security?error=Can%20not%20make%20admin.%20The%20password%20was%20invalid.")
    .end((Response response) => {
      collection.byId("2").getScopes().should.not.contain("admin");
    });
}
