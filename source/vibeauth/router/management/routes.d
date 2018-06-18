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
  }

  /// Initalize the object
  this(UserCollection userCollection, IMailQueue mailQueue,  ServiceConfiguration configuration = ServiceConfiguration.init) {
    this.configuration = configuration;
    this.userCollection = userCollection;
    this.mailQueue = mailQueue;
  }

  /// Generic handler for all user management routes
  void handler(HTTPServerRequest req, HTTPServerResponse res) {
    if(req.method == HTTPMethod.GET && req.path == configuration.paths.userManagement.list) {
      list(req, res);
    }

    if(req.method == HTTPMethod.GET && isUserPage(configuration.paths.userManagement.profile, req.path)) {
      profilePage(req, res);
    }
    
    if(req.method == HTTPMethod.POST && isUserPage(configuration.paths.userManagement.updateProfile, req.path)) {
      updateProfile(req, res);
    }

    if(req.method == HTTPMethod.GET &&  isUserPage(configuration.paths.userManagement.account, req.path)) {
      accountPage(req, res);
    }

    if(req.method == HTTPMethod.POST &&  isUserPage(configuration.paths.userManagement.updateAccount, req.path)) {
      updateAccountPage(req, res);
    }

    if(req.method == HTTPMethod.GET && isUserPage(configuration.paths.userManagement.security, req.path)) {
      securityPage(req, res);
    }
  }

  /// Render the user list
  void list(HTTPServerRequest req, HTTPServerResponse res) {
    scope auto view = new UserManagementListView(configuration, userCollection);

    res.writeBody(view.render, 200, "text/html; charset=UTF-8");
  }

  void profilePage(HTTPServerRequest req, HTTPServerResponse res) {
    scope auto view = new ProfileView(configuration);

    view.data.set(":id", configuration.paths.userManagement.profile, req.path);

    if("message" in req.query) {
      view.data.addMessage(req.query["message"]);
    }
    
    if("error" in req.query) {
      view.data.addError(req.query["error"]);
    }

    auto user = userCollection.byId(view.data.get(":id"));
    view.data.add("userData", user.toJson);

    res.writeBody(view.render, 200, "text/html; charset=UTF-8");
  }

  void updateProfile(HTTPServerRequest req, HTTPServerResponse res) {
    TemplateData data;
    data.set(":id", configuration.paths.userManagement.updateProfile, req.path);
    auto user = userCollection.byId(data.get(":id"));

    auto path = req.fullURL;
    auto destinationPath = configuration.paths.userManagement.profile.replace(":id", user.id);
    destinationPath = path.schema ~ "://" ~ path.host ~ ":" ~ path.port.to!string ~ destinationPath;

    if("name" !in req.form || "username" !in req.form) {
      string error = `?error=Missing%20data.The%20request%20can%20not%20be%20processed.`;

      res.redirect(destinationPath ~ error, 302);
      return;
    }

    string name = req.form["name"].strip.escapeHtmlString;
    string username = req.form["username"].strip.escapeHtmlString;

    if(username == "") {
      string error = `?error=The%20username%20is%20mandatory.`;

      res.redirect(destinationPath ~ error, 302);
      return;
    }

    auto ctr = ctRegex!(`[a-zA-Z][a-zA-Z0-9_\-]*`);
    auto result = matchFirst(username, ctr);

    if(result.empty || result.front != username) {
      string error = "?error=Username may only contain alphanumeric characters or single hyphens, and it must start with an alphanumeric character.";
    
      res.redirect(destinationPath ~ error.replace(" ", "%20"), 302);
      return;
    }

    user.name = name;
    user.username = username;

    string message = "?message=Profile%20updated%20successfully";

    res.redirect(destinationPath ~ message, 302);
  }

  void updateAccountPage(HTTPServerRequest req, HTTPServerResponse res) {
    TemplateData data;
    data.set(":id", configuration.paths.userManagement.updateAccount, req.path);
    auto user = userCollection.byId(data.get(":id"));

    auto path = req.fullURL;
    auto destinationPath = configuration.paths.userManagement.account.replace(":id", user.id);
    destinationPath = path.schema ~ "://" ~ path.host ~ ":" ~ path.port.to!string ~ destinationPath;
    string message;

    string[] missingFields;

    if("oldPassword" !in req.form) {
      missingFields ~= "oldPassword";
    }

    if("newPassword" !in req.form) {
      missingFields ~= "newPassword";
    }

    if("confirmPassword" !in req.form) {
      missingFields ~= "confirmPassword";
    }

    if(missingFields.length > 0) {
      message = "?error=" ~ missingFields.join(",%20") ~ "%20fields%20are%20missing";
      res.redirect(destinationPath ~ message, 302);
      return;
    }
    
    string oldPassword = req.form["oldPassword"];
    string newPassword = req.form["newPassword"];
    string confirmPassword = req.form["confirmPassword"];

    if(confirmPassword != newPassword) {
      message = "?error=Password%20confirmation%20doesn't%20match%20the%20password";
      res.redirect(destinationPath ~ message, 302);
      return;
    }

    if(newPassword.length < 10) {
      message = "?error=The%20new%20password%20is%20less%20then%2010%20chars";
      res.redirect(destinationPath ~ message, 302);
      return;
    }

    if(user.isValidPassword(oldPassword)) {
      user.setPassword(newPassword);
      message = "?message=Password%20updated%20successfully";
    } else {
      message = "?error=Old%20password%20isn't%20valid";
    }

    res.redirect(destinationPath ~ message, 302);
  }

  void accountPage(HTTPServerRequest req, HTTPServerResponse res) {
    scope auto view = new AccountView(configuration);

    view.data.set(":id", configuration.paths.userManagement.account, req.path);

    if("message" in req.query) {
      view.data.addMessage(req.query["message"]);
    }
    
    if("error" in req.query) {
      view.data.addError(req.query["error"]);
    }

    res.writeBody(view.render, 200, "text/html; charset=UTF-8");
  }

  void securityPage(HTTPServerRequest req, HTTPServerResponse res) {
    scope auto view = new SecurityView(configuration);

    view.data.set(":id", configuration.paths.userManagement.security, req.path);

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

/// It should update the user data
unittest {
  testRouter
    .request
    .post("/admin/users/1/update")
    .send(["name": " some name ", "username": " some-user-name "])
    .expectStatusCode(302)
    .expectHeader("Location", "http://localhost:0/admin/users/1?message=Profile%20updated%20successfully")
    .end((Response response) => {
      auto user = collection.byId("1");
      user.name.should.equal("some name");
      user.username.should.equal("some-user-name");
    });
}

/// It should not update the user data when the name is missing
unittest {
  testRouter
    .request
    .post("/admin/users/1/update")
    .send(["username": "some user name"])
    .expectStatusCode(302)
    .expectHeader("Location", "http://localhost:0/admin/users/1?error=Missing%20data.The%20request%20can%20not%20be%20processed.")
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
    .expectHeader("Location", "http://localhost:0/admin/users/1?error=Missing%20data.The%20request%20can%20not%20be%20processed.")
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
    .expectHeader("Location", "http://localhost:0/admin/users/1?message=Profile%20updated%20successfully")
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
    .expectHeader("Location", "http://localhost:0/admin/users/1/account?message=Password%20updated%20successfully")
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
    .expectHeader("Location", "http://localhost:0/admin/users/1/account?error=Old%20password%20isn't%20valid")
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
    .expectHeader("Location", "http://localhost:0/admin/users/1/account?error=Password%20confirmation%20doesn't%20match%20the%20password")
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
    .expectHeader("Location", "http://localhost:0/admin/users/1/account?error=oldPassword,%20newPassword,%20confirmPassword%20fields%20are%20missing")
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
    .expectHeader("Location", "http://localhost:0/admin/users/1/account?error=The%20new%20password%20is%20less%20then%2010%20chars")
    .end((Response response) => {
      collection.byId("1").isValidPassword("password").should.equal(true);
    });
}