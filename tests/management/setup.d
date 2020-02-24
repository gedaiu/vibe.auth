module tests.management.setup;

public import std.array;
public import std.datetime;
public import std.uri;

public import fluentasserts.vibe.request;
public import fluentasserts.vibe.json;
public import fluent.asserts;

public import vibeauth.data.token;
public import vibeauth.data.user;
public import vibeauth.data.usermodel;

public import vibeauth.collections.usermemory;

public import vibe.http.router;
public import vibe.data.json;

import vibeauth.router.management.routes;
import vibeauth.mail.base;

UserMemoryCollection collection;
User user;
TestMailQueue mailQueue;
Token activationToken;
Token authToken;
UserManagementRoutes userManagement;

alias MailMessage = vibeauth.mail.base.Message;

class TestMailQueue : MailQueue
{
  MailMessage[] messages;

  this() {
    super(EmailConfiguration());
  }

  override void addMessage(MailMessage message) {
    messages ~= message;
  }
}

auto testRouter() {
  auto router = new URLRouter();
  mailQueue = new TestMailQueue;

  collection = new UserMemoryCollection(["doStuff", "admin"]);
  user = new User("user@gmail.com", "password");
  user.name = "John Doe";
  user.username = "test";
  user.id = 1;

  collection.add(user);
  activationToken = collection.createToken(user.email, Clock.currTime + 3600.seconds, [], "activation");
  authToken = collection.createToken(user.email, Clock.currTime + 3600.seconds, [], "webLogin");

  userManagement = new UserManagementRoutes(collection, mailQueue);

  router.any("*", &userManagement.handler);
  return router;
}