module vibeauth.router.management.responses;

import std.string;
import std.regex;
import std.conv;
import std.algorithm;

import vibe.data.json;
import vibe.http.router;

import vibeauth.users;
import vibeauth.configuration;
import vibeauth.templatedata;
import vibeauth.router.request;

class UserManagementListView : View {
  private {
    const ServiceConfiguration configuration;
    UserCollection userCollection;
  }

  this(const ServiceConfiguration configuration, UserCollection userCollection) {
    this.configuration = configuration;
    this.userCollection = userCollection;

    super(configuration.templates.userManagement.listTemplate, configuration.serializeToJson);
  }

  override string generateBody() {
    string listPage = `<table class="table"><tbody>`;

    foreach(user; userCollection) {
      listPage ~= `<tr>` ~ 
      `<th>` ~ user.username ~ `</th>` ~ 
      `<td>` ~ user.email ~ `</td>` ~
       `<td><a href="` ~ configuration.paths.userManagement.profile.replace(":id", user.id) ~ `">Edit</a></td>`~ 
       `</tr>`;
    }

    listPage ~= `</tbody></table>`;

    return listPage;
  }
}

alias UserView(string T) = BasicView!("configuration.templates.userManagement.userTemplate", T);

alias ProfileView  = UserView!"configuration.templates.userManagement.profileForm";
alias AccountView  = UserView!"configuration.templates.userManagement.accountForm";
alias SecurityView = UserView!"configuration.templates.userManagement.securityForm";
alias DeleteView   = UserView!"configuration.templates.userManagement.deleteQuestion";

interface IController {
  bool canHandle(HTTPServerRequest);
  void handle(HTTPServerRequest req, HTTPServerResponse res);
}

abstract class PathController(string method, string configurationPath) : IController {
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
    mixin("auto method = HTTPMethod." ~ method ~ ";");
    if(req.method != method) {
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
    logedUser = req.getUser(userCollection);

    if(logedUser is null) {
      auto requestPath = req.fullURL;
      auto destinationPath = requestPath.schema ~ "://" ~ requestPath.host ~ ":" ~ requestPath.port.to!string ~
        configuration.paths.login.form;

      res.redirect(destinationPath, 302);
      return;
    }
  
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

alias ProfileController  = UserController!("paths.userManagement.profile", ProfileView);
alias AccountController  = UserController!("paths.userManagement.account", AccountView);
alias DeleteController   = UserController!("paths.userManagement.deleteAccount", DeleteView);

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

class RedirectView {
  private {
    HTTPServerRequest req;
    HTTPServerResponse res;
    string path;
  }

  this(HTTPServerRequest req, HTTPServerResponse res, string path) {
    this.req = req;
    this.res = res;
    this.path = path;
  }

  string destinationPath() {
    auto requestPath = req.fullURL;
    auto destinationPath = path.replace(":id", req.context["userId"].to!string);

    return requestPath.schema ~ "://" ~ requestPath.host ~ ":" ~ requestPath.port.to!string ~ destinationPath;
  }

  void respondError(string value) {
    string message = `?error=` ~ value.replace(" ", "%20");

    res.redirect(destinationPath ~ message, 302);
  }

  void respondMessage(string value) {
    string message = `?message=` ~ value.replace(" ", "%20");

    res.redirect(destinationPath ~ message, 302);
  }
}

class UpdateProfileController : PathController!("POST", "paths.userManagement.updateProfile") {
  this(UserCollection userCollection, ServiceConfiguration configuration) {
    super(userCollection, configuration);
  }

  void handle(HTTPServerRequest req, HTTPServerResponse res) {
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

class DeleteAccountController : PathController!("POST", "paths.userManagement.deleteAccount") {
    this(UserCollection userCollection, ServiceConfiguration configuration) {
    super(userCollection, configuration);
  }

  void handle(HTTPServerRequest req, HTTPServerResponse res) {
    auto view = new RedirectView(req, res, configuration.paths.userManagement.account);

    TemplateData data;
    data.set(":id", configuration.paths.userManagement.deleteAccount, req.path);
    auto user = userCollection.byId(data.get(":id"));

    auto path = req.fullURL;
    auto destinationPath = configuration.paths.userManagement.account.replace(":id", user.id);
    destinationPath = path.schema ~ "://" ~ path.host ~ ":" ~ path.port.to!string ~ destinationPath;

    if("password" !in req.form) {
      view.respondError("Can not remove user. The password was missing.");
      return;
    }

    auto password = req.form["password"];
    
    if(!user.isValidPassword(password)) {
      view.respondError("Can not remove user. The password was invalid.");
      return;
    }

    userCollection.remove(user.id);
    res.redirect(configuration.paths.location, 302);
  }


}
