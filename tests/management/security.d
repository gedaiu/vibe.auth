module tests.management.security;

import tests.management.setup;


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
