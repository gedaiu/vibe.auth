module vibeauth.router.registration.routes;

import std.stdio;
import std.datetime;
import std.algorithm;
import std.string;
import std.uri;

import vibe.http.router;
import vibe.data.json;
import vibe.inet.url;

import vibeauth.router.registration.responses;
import vibeauth.users;
import vibeauth.configuration;
import vibeauth.mail.base;
import vibeauth.challenges.base;
import vibeauth.router.accesscontrol;
import vibeauth.router.request;
import vibeauth.collection;
import vibeauth.templatedata;

/// Handle the registration routes
class RegistrationRoutes {

  private {
    UserCollection collection;
    IChallenge challenge;
    IMailQueue mailQueue;
    RegistrationResponses responses;

    const {
      ServiceConfiguration configuration;
    }
  }

  ///
  this(UserCollection collection, IChallenge challenge, IMailQueue mailQueue,
    const ServiceConfiguration configuration = ServiceConfiguration.init) {

    this.collection = collection;
    this.challenge = challenge;
    this.mailQueue = mailQueue;
    this.configuration = configuration;
    this.responses = new RegistrationResponses(challenge, configuration);
  }

  /// Handle the requests
  void handler(HTTPServerRequest req, HTTPServerResponse res) {
    try {
      setAccessControl(res);
      if(req.method == HTTPMethod.OPTIONS) {
        return;
      }

      if(req.method == HTTPMethod.GET && req.path == configuration.paths.registration.register) {
        responses.registerForm(req, res);
      }

      if(req.method == HTTPMethod.POST && req.path == configuration.paths.registration.addUser) {
        addUser(req, res);
      }

      if(req.method == HTTPMethod.GET && req.path == configuration.paths.registration.activation) {
        activation(req, res);
      }

      if(req.method == HTTPMethod.POST && req.path == configuration.paths.registration.activation) {
        newActivation(req, res);
      }

      if(req.method == HTTPMethod.GET && req.path == configuration.paths.registration.challange) {
        challenge.generate(req, res);
      }

      if(req.method == HTTPMethod.GET && req.path == configuration.paths.registration.confirmation) {
        responses.confirmationForm(req, res);
      }

    } catch(Exception e) {
      version(unittest) {} else debug stderr.writeln(e);

      if(!res.headerWritten) {
        res.writeJsonBody([ "error": ["message": e.msg] ], 500);
      }
    }
  }

  private {
    /// Activate an account
    void activation(HTTPServerRequest req, HTTPServerResponse res)
    {
      if("token" !in req.query || "email" !in req.query) {
        res.statusCode = 400;
        res.writeJsonBody(["error": ["message": "invalid request"]]);

        return;
      }

      auto token = req.query["token"];
      auto email = req.query["email"];

      if(!collection.contains(email)) {
        res.statusCode = 400;
        res.writeJsonBody(["error": ["message": "invalid request"]]);

        return;
      }

      auto user = collection[email];

      if(!user.isValidToken(token)) {
        res.statusCode = 400;
        res.writeJsonBody(["error": ["message": "invalid request"]]);

        return;
      }

      user.isActive = true;
      user.getTokensByType("activation").each!(a => user.revoke(a.name));

      res.redirect(configuration.paths.registration.activationRedirect);
    }

    string queryUserData(const RequestUserData userData, string error = "")
    {
      string query = "?error=" ~ encodeComponent(error);

      if(userData.name != "") {
        query ~= "&name=" ~ encodeComponent(userData.name);
      }

      if(userData.username != "") {
        query ~= "&username=" ~ encodeComponent(userData.username);
      }

      if(userData.email != "") {
        query ~= "&email=" ~ encodeComponent(userData.email);
      }
      return query;
    }

    string[string] activationVariables()
    {
      string[string] variables;

      variables["activation"] = configuration.paths.registration.activation;
      variables["serviceName"] = configuration.name;
      variables["location"] = configuration.paths.location;

      return variables;
    }

    void newActivation(HTTPServerRequest req, HTTPServerResponse res)
    {
      auto requestData = const RequestUserData(req);

      try {
        auto user = collection[requestData.email];

        if(!user.isActive) {
          auto tokens = user.getTokensByType("activation");
          if(!tokens.empty) {
            user.revoke(tokens.front.name);
          }

          auto token = collection.createToken(user.email, Clock.currTime + 3600.seconds, [], "activation");
          mailQueue.addActivationMessage(user.email, token, activationVariables);
        }
      } catch (ItemNotFoundException e) {
        version(unittest) {{}} else { debug e.writeln; }
      }

      responses.success(req, res);
    }

    void addUser(HTTPServerRequest req, HTTPServerResponse res)
    {
      immutable bool isJson = req.contentType.toLower.indexOf("json") > -1;
      auto requestData = const RequestUserData(req);

      try {
        requestData.validateUser;

        if(!challenge.validate(req, res, requestData.response)) {
          throw new Exception("Invalid challenge `response`");
        }

        if(collection.contains(requestData.email)) {
          throw new Exception("Email has already been taken");
        }

        if(collection.contains(requestData.username)) {
          throw new Exception("Username has already been taken");
        }
      } catch (Exception e) {
        if(isJson) {
          res.statusCode = 400;
          res.writeJsonBody(["error": ["message": e.msg ]]);
        } else {
          res.redirect(configuration.paths.registration.register ~ queryUserData(requestData, e.msg));
        }

        return;
      }

      UserData data;
      data.name = requestData.name;
      data.username = requestData.username;
      data.email = requestData.email;
      data.isActive = false;

      collection.createUser(data, requestData.password);
      auto token = collection.createToken(data.email, Clock.currTime + 3600.seconds, [], "activation");
      mailQueue.addActivationMessage(requestData.email, token, activationVariables);

      if(isJson) {
        res.statusCode = 201;
        res.writeVoidBody;
      } else {
        responses.success(req, res);
      }
    }
  }
}

version(unittest) {
  import std.array;
  import fluentasserts.vibe.request;
  import fluentasserts.vibe.json;
  import fluent.asserts;
  import vibeauth.token;

  UserMemmoryCollection collection;
  User user;
  RegistrationRoutes registration;
  TestMailQueue mailQueue;
  Token activationToken;

  alias MailMessage = vibeauth.mail.base.Message;

  class TestMailQueue : MailQueue
  {
    MailMessage[] messages;

    this() {
      super(EmailConfiguration());
    }

    override
    void addMessage(MailMessage message) {
      messages ~= message;
    }
  }

  class TestChallenge : IChallenge {
    string generate(HTTPServerRequest, HTTPServerResponse) {
      return "123";
    }

    bool validate(HTTPServerRequest, HTTPServerResponse, string response) {
      return response == "123";
    }

    string getTemplate(string challangeLocation) {
      return "";
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

    registration = new RegistrationRoutes(collection, new TestChallenge, mailQueue);

    router.any("*", &registration.handler);
    return router;
  }
}

@("POST valid data should create the user")
unittest {
  auto router = testRouter;

  auto data = `{
    "name": "test",
    "username": "test_user",
    "email": "test@test.com",
    "password": "testPassword",
    "response": "123"
  }`.parseJsonString;

  router
    .request
    .post("/register/user")
    .send(data)
    .expectStatusCode(200)
    .end((Response response) => {
      collection.contains("test@test.com").should.be.equal(true);

      collection["test@test.com"].name.should.equal("test");
      collection["test@test.com"].username.should.equal("test_user");
      collection["test@test.com"].email.should.equal("test@test.com");
      collection["test@test.com"].isActive.should.equal(false);
      collection["test@test.com"].isValidPassword("testPassword").should.equal(true);

      auto tokens = collection["test@test.com"].getTokensByType("activation").array;

      tokens.length.should.equal(1);
      collection["test@test.com"].isValidToken(tokens[0].name).should.equal(true);
    });
}

@("POST empty password should not create the user")
unittest {
  auto router = testRouter;
  auto data = `{
    "name": "test",
    "username": "test_user",
    "email": "test@test.com",
    "password": "",
    "response": "123"
  }`.parseJsonString;

  router
    .request
    .header("Content-Type", "application/json")
    .post("/register/user")
    .send(data)
    .expectStatusCode(400)
    .end((Response response) => {
      response.bodyJson.keys.should.contain("error");
      response.bodyJson["error"].keys.should.contain("message");
    });
}

@("POST short password should not create the user")
unittest {
  auto router = testRouter;

  auto data = `{
    "name": "test",
    "username": "test_user",
    "email": "test@test.com",
    "password": "123456789",
    "response": "123"
  }`.parseJsonString;

  router
    .request
    .header("Content-Type", "application/json")
    .post("/register/user")
    .send(data)
    .expectStatusCode(400)
    .end((Response response) => {
      response.bodyJson.keys.should.contain("error");
      response.bodyJson["error"].keys.should.contain("message");
    });
}

@("POST with and existing email should fail")
unittest {
  auto router = testRouter;

  auto data = `{
    "name": "test",
    "username": "test",
    "email": "test_user@gmail.com",
    "password": "12345678910",
    "response": "123"
  }`.parseJsonString;

  router
    .request
    .header("Content-Type", "application/json")
    .post("/register/user")
    .send(data)
    .expectStatusCode(400)
    .end((Response response) => {
      response.bodyJson.keys.should.contain("error");
      response.bodyJson["error"].keys.should.contain("message");
    });
}

@("POST with and existing username should fail")
unittest {
  auto router = testRouter;

  auto data = `{
    "name": "test",
    "username": "test_user",
    "email": "user@gmail.com",
    "password": "12345678910",
    "response": "123"
  }`.parseJsonString;

  router
    .request
    .header("Content-Type", "application/json")
    .post("/register/user")
    .send(data)
    .expectStatusCode(400)
    .end((Response response) => {
      response.bodyJson.keys.should.contain("error");
      response.bodyJson["error"].keys.should.contain("message");
    });
}

@("POST valid data should send a validation email")
unittest {
  auto router = testRouter;

  auto data = `{
    "name": "test",
    "username": "test_user",
    "email": "test@test.com",
    "password": "testPassword",
    "response": "123"
  }`.parseJsonString;

  router
    .request
    .post("/register/user")
    .send(data)
    .expectStatusCode(200)
    .end((Response response) => {
      string activationLink = "http://localhost/register/activation?email=test@test.com&token="
        ~ collection["test@test.com"].getTokensByType("activation").front.name;

      mailQueue.messages.length.should.equal(1);
      mailQueue.messages[0].textMessage.should.contain(activationLink);
      mailQueue.messages[0].htmlMessage.should.contain(`<a href="` ~ activationLink ~ `">`);
    });
}

@("GET with valid token should validate the user")
unittest {
  auto router = testRouter;

  collection["user@gmail.com"].isActive.should.equal(false);

  router
    .request
    .get("/register/activation?email=user@gmail.com&token=" ~ activationToken.name)
    .expectStatusCode(302)
    .end((Response response) => {
      collection["user@gmail.com"].isValidToken(activationToken.name).should.equal(false);
      collection["user@gmail.com"].isActive.should.equal(true);
    });
}

@("GET with invalid token should not validate the user")
unittest {
  auto router = testRouter;

  collection["user@gmail.com"].isActive.should.equal(false);

  router
    .request
    .get("/register/activation?email=user@gmail.com&token=other")
    .expectStatusCode(400)
    .end((Response response) => {
      collection["user@gmail.com"].isValidToken(activationToken.name).should.equal(true);
      collection["user@gmail.com"].isActive.should.equal(false);
    });
}

@("POST with valid email should send a new token to the inactive user")
unittest {
  auto router = testRouter;

  collection["user@gmail.com"].isActive.should.equal(false);

  router
    .request
    .post("/register/activation?email=user@gmail.com")
    .expectStatusCode(200)
    .end((Response response) => {
      string activationLink = "http://localhost/register/activation?email=user@gmail.com&token="
        ~ collection["user@gmail.com"].getTokensByType("activation").front.name;

      mailQueue.messages.length.should.equal(1);
      mailQueue.messages[0].textMessage.should.contain(activationLink);
      mailQueue.messages[0].htmlMessage.should.contain(`<a href="` ~ activationLink ~ `">`);
    });
}

@("POST with valid email should not send a new token to the active user")
unittest {
  auto router = testRouter;

  collection["user@gmail.com"].isActive(true);

  router
    .request
    .post("/register/activation?email=user@gmail.com")
    .expectStatusCode(200)
    .end((Response response) => {
      mailQueue.messages.length.should.equal(0);
    });
}

@("POST with invalid email should respond with 200 page")
unittest {
  auto router = testRouter;

  router
    .request
    .post("/register/activation?email=ola.com")
    .expectStatusCode(200)
    .end((Response response) => {
      mailQueue.messages.length.should.equal(0);
    });
}

@("POST with missing data should return an error")
unittest {
  auto router = testRouter;

  auto data = `{
    "username": "test_user",
    "email": "test@test.com",
    "password": "testPassword",
    "response": "123"
  }`.parseJsonString;

  router
    .request
    .post("/register/user")
    .send(data)
    .header("Content-Type", "application/json")
    .expectStatusCode(400)
    .end((Response response) => {
      response.bodyJson.keys.should.contain("error");
      response.bodyJson["error"].keys.should.contain("message");
    });

  data = `{
    "name": "test",
    "email": "test@test.com",
    "password": "testPassword",
    "response": "123"
  }`.parseJsonString;

  router
    .request
    .post("/register/user")
    .send(data)
    .header("Content-Type", "application/json")
    .expectStatusCode(400)
    .end((Response response) => {
      response.bodyJson.keys.should.contain("error");
      response.bodyJson["error"].keys.should.contain("message");
    });

  data = `{
    "name": "test",
    "username": "test_user",
    "password": "testPassword",
    "response": "123"
  }`.parseJsonString;

  router
    .request
    .post("/register/user")
    .send(data)
    .header("Content-Type", "application/json")
    .expectStatusCode(400)
    .end((Response response) => {
      response.bodyJson.keys.should.contain("error");
      response.bodyJson["error"].keys.should.contain("message");
    });

  data = `{
    "name": "test",
    "username": "test_user",
    "email": "test@test.com",
    "response": "123"
  }`.parseJsonString;

  router
    .request
    .post("/register/user")
    .send(data)
    .header("Content-Type", "application/json")
    .expectStatusCode(400)
    .end((Response response) => {
      response.bodyJson.keys.should.contain("error");
      response.bodyJson["error"].keys.should.contain("message");
    });

  data = `{
    "name": "test",
    "username": "test_user",
    "email": "test@test.com",
    "password": "testPassword"
  }`.parseJsonString;

  router
    .request
    .post("/register/user")
    .send(data)
    .header("Content-Type", "application/json")
    .expectStatusCode(400)
    .end((Response response) => {
      response.bodyJson.keys.should.contain("error");
      response.bodyJson["error"].keys.should.contain("message");
    });
}

@("POST with wrong response should return an error")
unittest {
  auto router = testRouter;

  auto data = `{
    "name": "test",
    "username": "test_user",
    "email": "test@test.com",
    "password": "testPassword",
    "response": "abc"
  }`.parseJsonString;

  router
    .request
    .post("/register/user")
    .send(data)
    .header("Content-Type", "application/json")
    .expectStatusCode(400)
    .end((Response response) => {
      response.bodyJson.keys.should.contain("error");
      response.bodyJson["error"].keys.should.contain("message");
    });
}
