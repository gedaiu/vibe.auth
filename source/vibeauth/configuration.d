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

  /// The service base URL. Url used for redireaction and email links
  string location = "http://localhost";

  /// A custom style file embedded in the auth html files
  string style;
}

/// Configurations for the registration process
struct RegistrationConfiguration {
  /// Path definitions
  RegistrationConfigurationPaths paths;

  /// Html templaes used in the registration process
  RegistrationConfigurationTemplates templates;
}

/// Registration process url paths
struct RegistrationConfigurationPaths {
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
struct RegistrationConfigurationTemplates {
  ///
  string form;
  ///
  string confirmation;
  ///
  string success;
}

/// Paths for the login process
struct LoginConfigurationPaths {
  ///
  string form = "/login";
  ///
  string login = "/login/check";

  ///
  string resetForm = "/login/reset";
  ///
  string reset = "/login/reset/send";

  ///
  string changePassword =  "/login/reset/change";

  ///
  string redirect = "/";
}

/// Html templates for the login process
struct LoginConfigurationTemplates {
  ///
  string login;
  ///
  string reset;
}

/// Configuration for the login process
struct LoginConfiguration {
  /// Paths for the login process
  LoginConfigurationPaths paths;
  
  /// Html templates for the login process
  LoginConfigurationTemplates templates;

  /// Login cookie expiration time
  ulong loginTimeoutSeconds = 86_400;
}
