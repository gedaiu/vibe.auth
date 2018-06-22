module tests.management.delete_;

import tests.management.setup;


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