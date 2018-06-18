/++
  A module containing the configuration structures used to setup your auth process

  Copyright: © 2018 Szabo Bogdan
  License: Subject to the terms of the MIT license, as written in the included LICENSE.txt file.
  Authors: Szabo Bogdan
+/
module vibeauth.configuration;

import vibe.data.json;
import std.file;

version(unittest) {
  import fluent.asserts;
}

/// Structure used to define a service
struct ServiceConfiguration {
  /// The service name
  string name = "Unknown App";

  /// A custom style file embedded in the auth html files
  string style;

  /// Login cookie expiration time
  ulong loginTimeoutSeconds = 86_400;

  ///
  Paths paths;

  ///
  Templates templates;

  /// Load configuration from a Json object
  void load(Json data) {
    if("name" in data) {
      name = data["name"].to!string;
    }

    if("style" in data) {
      style = data["style"].to!string;
    }

    if("loginTimeoutSeconds" in data) {
      loginTimeoutSeconds = data["loginTimeoutSeconds"].to!ulong;
    }

    if("paths" in data && data["paths"].type == Json.Type.object) {
      paths.load(data["paths"]);
    }

    if("templates" in data && data["templates"].type == Json.Type.object) {
      templates.load(data["templates"]);
    }
  }
}

/// load configuration
unittest {
  auto config = `{
    "name": "demo",
    "style": "some style",
    "loginTimeoutSeconds": 100,
    "paths": {
      "location": "location"
    }
  }`.parseJsonString;

  ServiceConfiguration configuration;
  configuration.load(config);

  configuration.name.should.equal("demo");
  configuration.style.should.equal("some style");
  configuration.loginTimeoutSeconds.should.equal(100);
  configuration.paths.location.should.equal("location");
}

///
struct Paths {
  /// The service base URL. Url used for redireaction and email links
  string location = "http://localhost";

  ///
  RegistrationPaths registration;

  ///
  LoginPaths login;

  ///
  UserManagementPaths userManagement;


  /// Load configuration from a Json object
  void load(Json data) {
    if("location" in data) {
      location = data["location"].to!string;
    }

    if("registration" in data) {
      registration.load(data["registration"]);
    }

    if("registration" in data) {
      login.load(data["login"]);
    }

    if("registration" in data) {
      userManagement.load(data["userManagement"]);
    }
  }
}

///
struct Templates {
  mixin ObjectLoader;

  ///
  RegistrationTemplates registration;

  ///
  LoginTemplates login;

  ///
  UserManagementTemplates userManagement;
}

/// Registration process url paths
struct RegistrationPaths {
  mixin StringLoader;

  /// 
  string register = "/register";
  ///
  string addUser = "/register/user";
  ///
  string activation = "/register/activation";
  ///
  string challange = "/register/challenge";
  ///
  string confirmation = "/register/confirmation";
  ///
  string activationRedirect = "/";
}

/// Html templaes used in the registration process
struct RegistrationTemplates {
  mixin FileLoader;

  ///
  string formTemplate = import("register/formTemplate.html");

  ///
  string form = import("register/form.html");

  ///
  string confirmationTemplate = import("register/confirmationTemplate.html");
  ///
  string confirmation = import("register/confirmation.html");;
  
  ///
  string successTemplate = import("register/successTemplate.html");
  ///
  string success = import("register/success.html");
}

/// Paths for the login process
struct LoginPaths {
  mixin StringLoader;

  ///
  string form = "/login";

  ///
  string login = "/login/check";

  ///
  string resetForm = "/login/reset";

  ///
  string reset = "/login/reset/send";

  ///
  string changePassword = "/login/reset/change";

  ///
  string redirect = "/";
}

/// Html templates for the login process
struct LoginTemplates {
  mixin FileLoader;

  ///
  string formTemplate = import("login/formTemplate.html");
  ///
  string form = import("login/form.html");

  ///
  string resetTemplate = import("login/resetTemplate.html");
  ///
  string reset = import("login/reset.html");
  ///
  string resetPassword = import("login/resetPasswordForm.html");
}

struct UserManagementPaths {
  mixin StringLoader;

  ///
  string deleteAccount = "/admin/users/:id/delete";
  ///
  string list = "/admin/users";

  ///
  string profile = "/admin/users/:id";
  ///
  string updateProfile = "/admin/users/:id/update";

  ///
  string account = "/admin/users/:id/account";
  ///
  string accountProfile = "/admin/users/:id/account/update";

  ///
  string security = "/admin/users/:id/security";
  ///
  string securityProfile = "/admin/users/:id/security/update";
}

struct UserManagementTemplates {
  mixin FileLoader;

  ///
  string listTemplate = import("userManagement/template.html");

  ///
  string userTemplate = import("userManagement/userTemplate.html");

  ///
  string profileForm = import("userManagement/profileForm.html");

  ///
  string accountForm = import("userManagement/accountForm.html");

  ///
  string securityForm = import("userManagement/securityForm.html");
}

mixin template FileLoader() {
  /// Load configuration from a Json object
  void load(Json data) {
    static foreach(member; __traits(allMembers, typeof(this))) {
      static if(member != "load") {
        if(member in data && data[member].type == Json.Type.string) {
          string fileName = data[member].to!string;
          mixin("this." ~ member ~ " = readText(fileName);");
        }
      }
    }
  }
}

mixin template ObjectLoader() {
  /// Load configuration from a Json object
  void load(Json data) {
    static foreach(member; __traits(allMembers, typeof(this))) {
      static if(member != "load") {
        if(member in data && data[member].type == Json.Type.object) {
          mixin("this." ~ member ~ ".load(data[\"" ~ member ~ "\"]);");
        }
      }
    }
  }
}

mixin template StringLoader() {
  /// Load configuration from a Json object
  void load(Json data) {
    static foreach(member; __traits(allMembers, typeof(this))) {
      static if(member != "load") {
        if(member in data && data[member].type == Json.Type.object) {
          mixin("this." ~ member ~ " = data[\"" ~ member ~ "\"].to!string;");
        }
      }
    }
  }
}
