module tests.management.account;

import tests.management.setup;

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