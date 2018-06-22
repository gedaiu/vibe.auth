module tests.management.adminRights;

import tests.management.setup;


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
