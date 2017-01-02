module vibeauth.router.registration;

import std.stdio;

import vibe.http.router;
import vibe.data.json;
import vibe.inet.url;

import vibeauth.users;

class RegistrationRoutes {

  private {
    UserCollection collection;
  }

  this(UserCollection collection) {
    this.collection = collection;
  }

  void addUser(HTTPServerRequest req, HTTPServerResponse res) {
    UserData data;

    data.name = req.json["name"].to!string;
    data.username = req.json["username"].to!string;
    data.email = req.json["email"].to!string;
    data.isActive = false;

    collection.createUser(data, req.json["password"].to!string);

    res.statusCode = 200;
    res.writeVoidBody;
  }
}

version(unittest) {
  import http.request;
  import http.json;
  import bdd.base;
  import vibeauth.token;

  UserMemmoryCollection collection;
  User user;
  RegistrationRoutes registration;
  Token refreshToken;

  auto testRouter() {
    auto router = new URLRouter();

    collection = new UserMemmoryCollection(["doStuff"]);
  	user = new User("user@gmail.com", "password");
    user.name = "John Doe";
    user.username = "test";
    user.id = 1;

  	collection.add(user);

    registration = new RegistrationRoutes(collection);
    router.post("/register/user", &registration.addUser);

    return router;
  }
}

@("POST valid credentials should create the user")
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
    });
}
