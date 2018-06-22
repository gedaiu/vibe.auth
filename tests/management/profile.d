module tests.management.profile;

import tests.management.setup;

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