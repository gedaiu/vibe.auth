/++
  A module containing the configuration structures used to setup your auth process

  Copyright: © 2018 Szabo Bogdan
  License: Subject to the terms of the MIT license, as written in the included LICENSE.txt file.
  Authors: Szabo Bogdan
+/
module vibeauth.configuration;

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
}

///
struct Templates {
  ///
  RegistrationTemplates registration;

  ///
  LoginTemplates login;

  ///
  UserManagementTemplates userManagement;
}

/// Registration process url paths
struct RegistrationPaths {
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