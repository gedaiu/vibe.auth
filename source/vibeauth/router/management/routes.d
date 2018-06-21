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
      new ProfileController(userCollection, configuration),
      new UpdateProfileController(userCollection, configuration),

      new AccountController(userCollection, configuration),
      new UpdateAccountController(userCollection, configuration),

      new DeleteController(userCollection, configuration),
      new DeleteAccountController(userCollection, configuration),

      new SecurityController(userCollection, configuration)
    ];
  }

  /// Generic handler for all user management routes
  void handler(HTTPServerRequest req, HTTPServerResponse res) {
    if(req.method == HTTPMethod.GET && req.path == configuration.paths.userManagement.list) {
      list(req, res);
      return;
    }

    foreach(controller; controllers) {
      if(controller.canHandle(req)) {
        controller.handle(req, res);
        return;
      }
    }
  }

  /// Render the user list
  void list(HTTPServerRequest req, HTTPServerResponse res) {
    scope auto view = new UserManagementListView(configuration, userCollection);

    res.writeBody(view.render, 200, "text/html; charset=UTF-8");
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

    collection = new UserMemmoryCollection(["doStuff"]);
    user = new User("user@gmail.com", "password");
    user.name = "John Doe";
    user.username = "test";
    user.id = 1;

    collection.add(user);
    activationToken = collection.createToken(user.email, Clock.currTime + 3600.seconds, [], "activation");

    userManagement = new UserManagementRoutes(collection, mailQueue);

    router.any("*", &userManagement.handler);
    return router;
  }
}

/// It should render the user list
unittest {
  testRouter
    .request
    .get("/admin/users")
    .expectStatusCode(200)
    .end((Response response) => {
      response.bodyString.should.contain("user@gmail.com");
    });
}

/// It should render 404 when the user does not exist
unittest {
  testRouter
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

  auto user = new User("user2@gmail.com", "password");
  user.name = "John Doe";
  user.username = "other test";
  user.id = 2;

  collection.add(user);

  router
    .request
    .post("/admin/users/2/update")
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
    .send(["password": "invalid"])
    .expectStatusCode(302)
    .expectHeader("Location", "http://localhost:0/admin/users/1/account?error=Can%20not%20remove%20user.%20The%20password%20was%20invalid.")
    .end((Response response) => {
      collection.contains("user@gmail.com").should.equal(true);
    });
}

/// It should not remove an user if the password is missing
unittest {
  testRouter
    .request
    .post("/admin/users/1/delete")
    .send(["": "password"])
    .expectStatusCode(302)
    .expectHeader("Location", "http://localhost:0/admin/users/1/account?error=Can%20not%20remove%20user.%20The%20password%20was%20missing.")
    .end((Response response) => {
      collection.contains("user@gmail.com").should.equal(true);
    });
}