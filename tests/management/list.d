module tests.management.list;

import tests.management.setup;


/// It should render the user list
unittest {
  auto router = testRouter;
  collection.empower("user@gmail.com", "admin");
  
  router
    .request
    .get("/admin/users")
    .header("Cookie", "auth-token=" ~ authToken.name)
    .expectStatusCode(200)
    .end((Response response) => {
      response.bodyString.should.contain("user@gmail.com");
    });
}
