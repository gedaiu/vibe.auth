module vibeauth.router.management.views;

import std.string;
import std.conv;

import vibeauth.mvc.view;
import vibeauth.configuration;
import vibeauth.users;

import vibe.data.json;
import vibe.http.router;

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

alias UserView(string T) = BasicView!("templates.userManagement.userTemplate", T);

alias ProfileView  = UserView!"templates.userManagement.profileForm";
alias AccountView  = UserView!"templates.userManagement.accountForm";
alias SecurityView = UserView!"templates.userManagement.securityForm";
alias QuestionView = UserView!"templates.userManagement.question";

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
