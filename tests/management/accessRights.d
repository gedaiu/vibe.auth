module tests.management.accessRights;

import tests.management.setup;



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