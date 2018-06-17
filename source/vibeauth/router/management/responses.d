module vibeauth.router.management.responses;

import std.string;

import vibe.data.json;

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
