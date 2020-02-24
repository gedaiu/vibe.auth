module vibeauth.tests.collection.usermemory;

import fluent.asserts;
import vibeauth.collections.usermemory;
import vibeauth.data.user;
import std.datetime;
import std.algorithm;
import std.array;

/// Throw exceptions on selecting invalid users
unittest {
  auto collection = new UserMemoryCollection([]);
  auto user = new User("user", "password");

  collection.add(user);
  assert(collection["user"] == user, "It should return user by name");
  assert(collection.contains("user"), "It should find user by name");
  assert(!collection.contains("other user"), "It should not find user by name");

  ({
    collection["other user"];
  }).should.throwAnyException;
}

/// User access
unittest {
  auto collection = new UserMemoryCollection(["doStuff"]);
  auto user = new User("user", "password");
  user.id = 1;

  auto otherUser = new User("otherUser", "password");
  otherUser.id = 2;

  collection.add(user);
  collection.add(otherUser);
  collection.empower("user", "doStuff");

  assert(user.can!"doStuff", "It should return true if the user can `doStuff`");
  assert(!otherUser.can!"doStuff", "It should return false if the user can not `doStuff`");
}

/// Searching for a missing token
unittest {
  auto collection = new UserMemoryCollection([]);
  auto user = new User("user", "password");

  collection.add(user);
  auto token = user.createToken(Clock.currTime + 3600.seconds);

  collection.byToken(token.name).name.should.equal(user.name).because("It should find user by token");

  ({
    collection.byToken("token");
  }).should.throwAnyException;
}

/// Token revoke
unittest {
  auto collection = new UserMemoryCollection([]);
  auto user = new User("user", "password");

  collection.add(user);
  auto token = user.createToken(Clock.currTime + 3600.seconds);

  assert(collection.byToken(token.name) == user, "It should find user by token");

  collection.revoke(token.name);

  ({
    collection.byToken(token.name);
  }).should.throwAnyException;
}

/// Ignore expired tokens
unittest {
  auto collection = new UserMemoryCollection([]);
  auto user = new User("user", "password");

  collection.add(user);
  auto token = user.createToken(Clock.currTime - 1.seconds);

  ({
    collection.byToken(token.name);
  }).should.throwAnyException;
}

/// Get tokens by type
unittest {
  auto collection = new UserMemoryCollection([]);
  auto user = new User("user", "password");

  collection.add(user);
  auto token = user.createToken(Clock.currTime + 3600.seconds, [], "activation").name;
  auto tokens = collection["user"].getTokensByType("activation").map!(a => a.name).array;

  tokens.length.should.equal(1);
  tokens.should.contain(token);
}

/// Ignore expired tokens when searching by type
unittest {
  auto collection = new UserMemoryCollection([]);
  auto user = new User("user", "password");

  collection.add(user);
  user.createToken(Clock.currTime - 1.seconds, [], "activation");
  auto tokens = collection["user"].getTokensByType("activation").map!(a => a.name).array;

  tokens.length.should.equal(0);
}

/// Get user by id
unittest {
  auto collection = new UserMemoryCollection([]);
  auto user = new User("user", "password");
  user.id = 1;

  collection.add(user);
  auto result = collection.byId("1");

  result.id.should.equal("1");
}

/// Remove user by id
unittest {
  bool wasRemoved;

  void onRemove(User user) {
    wasRemoved = user.id == "1";
  }

  auto collection = new UserMemoryCollection([]);
  collection.onRemove = &onRemove;

  auto user = new User("user", "password");
  user.id = 1;

  collection.add(user);
  collection.remove("1");

  collection.length.should.equal(0);
  wasRemoved.should.equal(true);
}
