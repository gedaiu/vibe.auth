module vibeauth.router.management.responses;

import std.string;

import vibe.data.json;
import vibe.http.router;

import vibeauth.users;
import vibeauth.configuration;
import vibeauth.templatedata;

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

class UserController(string configurattionPath, View) {
  private {
    UserCollection userCollection;
    ServiceConfiguration configuration;
    string path;
  }

  this(UserCollection userCollection, ServiceConfiguration configuration) {
    this.userCollection = userCollection;
    this.configuration = configuration;

    mixin("path = configuration." ~ configurattionPath ~ ";");
  }

  bool canHandle(HTTPServerRequest req) {
    if(req.method != HTTPMethod.GET) {
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

  void handle(HTTPServerRequest req, HTTPServerResponse res) {
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

    res.writeBody(view.render, 200, "text/html; charset=UTF-8");
  }
}

alias ProfileController  = UserController!("paths.userManagement.profile", ProfileView);
alias AccountController  = UserController!("paths.userManagement.account", AccountView);
alias DeleteController   = UserController!("paths.userManagement.deleteAccount", DeleteView);
alias SecurityController = UserController!("paths.userManagement.security", SecurityView);
