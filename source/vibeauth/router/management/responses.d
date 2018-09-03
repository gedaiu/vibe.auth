module vibeauth.router.management.responses;

import std.string;
import std.regex;
import std.conv;
import std.algorithm;

import vibe.data.json;
import vibe.http.router;

import vibeauth.users;
import vibeauth.configuration;
import vibeauth.mvc.templatedata;
import vibeauth.mvc.view;
import vibeauth.mvc.controller;
import vibeauth.router.request;
import vibeauth.router.management.views;

bool validateRights(HTTPServerRequest req, HTTPServerResponse res, ServiceConfiguration configuration, UserCollection userCollection) {
  auto logedUser = req.getUser(userCollection);
  auto path = req.fullURL;
  
  if(logedUser is null) {
    res.redirect(path.schema ~ "://" ~ path.host ~ ":" ~ path.port.to!string ~ configuration.paths.login.form, 302);
    return false;
  }

  if("userId" !in req.context && !logedUser.can!("admin")) {
    return false;
  }

  if("userId" in req.context && logedUser.id != req.context["userId"].to!string && !logedUser.can!("admin")) {
    return false;
  }

  return true;
}

class UserController(string configurationPath, View) : PathController!("GET", configurationPath) {
  protected {
    User logedUser;
  }

  this(UserCollection userCollection, ServiceConfiguration configuration) {
    super(userCollection, configuration);
  }

  void handle(ref View view, User user) {
  }

  void handle(HTTPServerRequest req, HTTPServerResponse res) {
    if(!validateRights(req, res, configuration, userCollection)) {
      return;
    }

    logedUser = req.getUser(userCollection);
  
    scope(exit) {
      logedUser = null;
    }

    scope auto view = new View(configuration);

    view.data.set(":id", path, req.path);

    if("message" in req.query) {
      view.data.addMessage(req.query["message"]);
    }

    if("error" in req.query) {
      view.data.addError(req.query["error"]);
    }

    auto user = userCollection.byId(view.data.get(":id"));
    view.data.add("userData", user.toJson);

    handle(view, user);

    res.writeBody(view.render, 200, "text/html; charset=UTF-8");
  }
}

abstract class QuestionController(string configurationPath) : IController {
  protected {
    UserCollection userCollection;
    ServiceConfiguration configuration;
    string path;
  }

  this(UserCollection userCollection, ServiceConfiguration configuration) {
    this.userCollection = userCollection;
    this.configuration = configuration;

    mixin("path = configuration." ~ configurationPath ~ ";");
  }

  bool canHandle(HTTPServerRequest req) {
    if(req.method != HTTPMethod.GET && req.method != HTTPMethod.POST) {
      return false;
    }

    if(!isUserPage(path, req.path)) {
      return false;
    }

    TemplateData data;
    data.set(":id", path, req.path);

    try {
      userCollection.byId(data.get(":id"));
    } catch(UserNotFoundException) {
      return false;
    }

    req.context["userId"] = data.get(":id");

    return true;
  }

  abstract {
    string title();
    string question();
    string action();
    string backPath();
    string backPath(HTTPServerRequest);
  }

  void handleQuestion(HTTPServerRequest req, HTTPServerResponse res) {
    auto view = new QuestionView(configuration  );
    view.data.set(":id", path, req.path);

    view.data.add("title", title());
    view.data.add("question", question());
    view.data.add("action", action());
    view.data.add("path", req.fullURL.toString);
    view.data.add("path-back", backPath(req));

    res.writeBody(view.render, 200, "text/html; charset=UTF-8");
  }

  abstract void handleAction(HTTPServerRequest req, HTTPServerResponse res);

  void handle(HTTPServerRequest req, HTTPServerResponse res) {
    if(!validateRights(req, res, configuration, userCollection)) {
      return;
    }

    if(req.method == HTTPMethod.GET) {
      handleQuestion(req, res);
    }
    
    if(req.method == HTTPMethod.POST && isValidPassword(req, res)) {
      handleAction(req, res);
    }
  }

  bool isValidPassword(HTTPServerRequest req, HTTPServerResponse res) {
    auto logedUser = req.getUser(userCollection);

    if(logedUser is null) {
      res.redirect(backPath(req), 302);
      return false;
    }

    auto view = new RedirectView(req, res, backPath);

    if("password" !in req.form) {
      view.respondError("Can not " ~ title.toLower ~ ". The password was missing.");
      return false;
    }

    auto password = req.form["password"];
    
    if(!logedUser.isValidPassword(password)) {
      view.respondError("Can not " ~ title.toLower ~ ". The password was invalid.");
      return false;
    }

    return true;
  }
}

alias ProfileController  = UserController!("paths.userManagement.profile", ProfileView);
alias AccountController  = UserController!("paths.userManagement.account", AccountView);

class SecurityController : UserController!("paths.userManagement.security", SecurityView) {
  this(UserCollection userCollection, ServiceConfiguration configuration) {
    super(userCollection, configuration);
  }

  override void handle(ref SecurityView view, User user) {
    auto isAdmin = user.getScopes.canFind("admin");
    auto isLogedUser = logedUser.id == user.id;
    auto isLogedAdmin = logedUser.getScopes.canFind("admin");

    if(!isLogedAdmin) {
      view.data.add("rights", "");
      return;
    }

    scope View rightsView;

    if(isLogedUser) {
      rightsView = new View(configuration.templates.userManagement.adminRights, configuration.serializeToJson);
    } else {
      rightsView = new View(configuration.templates.userManagement.otherRights, configuration.serializeToJson);
    }

    Json roleData = Json.emptyObject;
    roleData["type"] = isAdmin ? "an administrator" : "not an administrator";
    roleData["class"] = isAdmin ? "info" : "secondary";
    roleData["action"] = isAdmin ? "revoke admin" : "make admin";

    auto link = isAdmin ?
      configuration.paths.userManagement.securityRevokeAdmin :
      configuration.paths.userManagement.securityMakeAdmin;

    roleData["link"] = link.replace(":id", view.data.get(":id"));

    rightsView.data.add("role", roleData);

    view.data.add("rights", rightsView.render);
  }
}

class ListController : PathController!("GET", "paths.userManagement.list") {
  this(UserCollection userCollection, ServiceConfiguration configuration) {
    super(userCollection, configuration);
  }

  void handle(HTTPServerRequest req, HTTPServerResponse res) {
    if(!validateRights(req, res, configuration, userCollection)) {
      return;
    }

    scope auto view = new UserManagementListView(configuration, userCollection);
    res.writeBody(view.render, 200, "text/html; charset=UTF-8");
  }
}

class UpdateProfileController : PathController!("POST", "paths.userManagement.updateProfile") {
  this(UserCollection userCollection, ServiceConfiguration configuration) {
    super(userCollection, configuration);
  }

  void handle(HTTPServerRequest req, HTTPServerResponse res) {
    if(!validateRights(req, res, configuration, userCollection)) {
      return;
    }

    auto view = new RedirectView(req, res, configuration.paths.userManagement.profile);

    string id = req.context["userId"].to!string;
    auto user = userCollection.byId(id);

    if("name" !in req.form || "username" !in req.form) {
      view.respondError("Missing data. The request can not be processed.");
      return;
    }

    string name = req.form["name"].strip.escapeHtmlString;
    string username = req.form["username"].strip.escapeHtmlString;

    if(username == "") {
      view.respondError("The username is mandatory.");
      return;
    }

    if(username != user.username && userCollection.contains(username)) {
      view.respondError("The new username is already taken.");
      return;
    }

    auto ctr = ctRegex!(`[a-zA-Z][a-zA-Z0-9_\-]*`);
    auto result = matchFirst(username, ctr);

    if(result.empty || result.front != username) {
      view.respondError("Username may only contain alphanumeric characters or single hyphens, and it must start with an alphanumeric character.");
      return;
    }

    user.name = name;
    user.username = username;

    view.respondMessage("Profile updated successfully.");
  }
}

class UpdateAccountController : PathController!("POST", "paths.userManagement.updateAccount") {
  this(UserCollection userCollection, ServiceConfiguration configuration) {
    super(userCollection, configuration);
  }

  void handle(HTTPServerRequest req, HTTPServerResponse res) {
    if(!validateRights(req, res, configuration, userCollection)) {
      return;
    }

    auto view = new RedirectView(req, res, configuration.paths.userManagement.account);

    string id = req.context["userId"].to!string;
    auto user = userCollection.byId(id);

    string[] missingFields;

    if("oldPassword" !in req.form) {
      missingFields ~= "oldPassword";
    }

    if("newPassword" !in req.form) {
      missingFields ~= "newPassword";
    }

    if("confirmPassword" !in req.form) {
      missingFields ~= "confirmPassword";
    }

    if(missingFields.length > 0) {
      view.respondError(missingFields.join(" ") ~ " fields are missing.");
      return;
    }
    
    string oldPassword = req.form["oldPassword"];
    string newPassword = req.form["newPassword"];
    string confirmPassword = req.form["confirmPassword"];

    if(confirmPassword != newPassword) {
      view.respondError("Password confirmation doesn't match the password.");
      return;
    }

    if(newPassword.length < 10) {
      view.respondError("The new password is less then 10 chars.");
      return;
    }

    if(user.isValidPassword(oldPassword)) {
      user.setPassword(newPassword);
      view.respondMessage("Password updated successfully.");
    } else {
      view.respondError("The old password is not valid.");
    }
  }
}

class DeleteAccountController : QuestionController!("paths.userManagement.deleteAccount") {

  this(UserCollection userCollection, ServiceConfiguration configuration) {
    super(userCollection, configuration);
  }

  override {
    string title() {
      return "Delete account";
    }

    string question() {
      return "Are you sure you want to delete this account?";
    }

    string action() {
      return "Delete";
    }

    string backPath() {
      return configuration.paths.userManagement.account;
    }

    string backPath(HTTPServerRequest req) {
      auto path = req.fullURL;
      auto destinationPath = backPath.replace(":id", req.context["userId"].to!string);
      return path.schema ~ "://" ~ path.host ~ ":" ~ path.port.to!string ~ destinationPath;
    }
  }

  override void handleAction(HTTPServerRequest req, HTTPServerResponse res) {
    userCollection.remove(req.context["userId"].to!string);
    res.redirect(configuration.paths.location, 302);
  }
}

class RevokeAdminController : QuestionController!("paths.userManagement.securityRevokeAdmin") {

  this(UserCollection userCollection, ServiceConfiguration configuration) {
    super(userCollection, configuration);
  }

  override {
    string title() {
      return "Revoke admin";
    }

    string question() {
      return "Are you sure you want to revoke the admin rights of this user?";
    }

    string action() {
      return "Revoke";
    }

    string backPath() {
      return configuration.paths.userManagement.security;
    }

    string backPath(HTTPServerRequest req) {
      auto path = req.fullURL;
      auto destinationPath = backPath.replace(":id", req.context["userId"].to!string);
      return path.schema ~ "://" ~ path.host ~ ":" ~ path.port.to!string ~ destinationPath;
    }
  }

  override void handleAction(HTTPServerRequest req, HTTPServerResponse res) {
    auto view = new RedirectView(req, res, configuration.paths.userManagement.account);

    TemplateData data;
    data.set(":id", path, req.path);
    userCollection.byId(data.get(":id")).removeScope("admin");

    res.redirect(backPath(req), 302);
  }
}

class MakeAdminController : QuestionController!("paths.userManagement.securityMakeAdmin") {

  this(UserCollection userCollection, ServiceConfiguration configuration) {
    super(userCollection, configuration);
  }

  override {
    string title() {
      return "Make admin";
    }

    string question() {
      return "Are you sure you want to add admin rights to this user?";
    }

    string action() {
      return "Approve";
    }

    string backPath() {
      return configuration.paths.userManagement.security;
    }

    string backPath(HTTPServerRequest req) {
      auto path = req.fullURL;
      auto destinationPath = backPath.replace(":id", req.context["userId"].to!string);
      return path.schema ~ "://" ~ path.host ~ ":" ~ path.port.to!string ~ destinationPath;
    }
  }

  override void handleAction(HTTPServerRequest req, HTTPServerResponse res) {
    auto view = new RedirectView(req, res, configuration.paths.userManagement.account);

    TemplateData data;
    data.set(":id", path, req.path);
    userCollection.byId(data.get(":id")).addScope("admin");

    res.redirect(backPath(req), 302);
  }
}