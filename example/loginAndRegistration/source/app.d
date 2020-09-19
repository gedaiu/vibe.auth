import std.stdio;
import std.path;
import std.file;

import vibeauth.challenges.mathcaptcha;
import vibeauth.challenges.recaptcha;
import vibeauth.client;

import vibeauth.configuration;
import vibeauth.router.registration.routes;
import vibeauth.router.login.routes;
import vibeauth.router.management.routes;
import vibeauth.mail.sendmail;
import vibeauth.mail.vibe;
import vibeauth.data.token;
import vibeauth.router.request;
import vibeauth.mail.base;
import vibeauth.router.resources.routes;

import vibe.d;

const {
  EmailConfiguration emailConfiguration;
  ServiceConfiguration serviceConfiguration;
}

UserMemoryCollection collection;

void handler(HTTPServerRequest req, HTTPServerResponse res) {
  const auto style = serviceConfiguration.style;

  User user = req.getUser(collection);

  res.render!("index.dt", style, user);
}

shared static this()
{
  /// Service setup
  auto configurationJson = readText("configuration.json").parseJsonString;
  configurationJson["email"]["activation"]["text"] = readText("emails/activation.txt");
  configurationJson["email"]["activation"]["html"] = readText("emails/activation.html");

  configurationJson["email"]["resetPassword"]["text"] = readText("emails/resetPassword.txt");
  configurationJson["email"]["resetPassword"]["html"] = readText("emails/resetPassword.html");

  configurationJson["email"]["resetPasswordConfirmation"]["text"] = readText("emails/resetPasswordConfirmation.txt");
  configurationJson["email"]["resetPasswordConfirmation"]["html"] = readText("emails/resetPasswordConfirmation.html");

  ServiceConfiguration serviceConfiguration;
  serviceConfiguration.load(configurationJson["service"]);

  emailConfiguration = configurationJson["email"].deserializeJson!EmailConfiguration;

  ///
  auto settings = new HTTPServerSettings;
  settings.port = 8888;

  collection = new UserMemoryCollection(["doStuff"]);

  /// Generate some users
  foreach(i; 1..1_000) {
    auto user = new User("user" ~ i.to!string ~ "@gmail.com", "password");
        user.name = "John Doe";
        user.username = "user" ~ i.to!string;
        user.id = i;

    if(i < 100) {
      user.isActive = true;
    }

    if(i < 10) {
      user.addScope("admin");
    }

    collection.add(user);
  }

  MathCaptchaSettings captchaSettings;
  captchaSettings.fontName = buildNormalizedPath(getcwd, "fonts/warpstorm/WarpStorm.otf");

  auto mailQueue = new VibeMailQueue(emailConfiguration);

  auto registrationRoutes = new RegistrationRoutes(collection,
    //new ReCaptcha("siteKey", "secretKey"),
    new MathCaptcha(captchaSettings),
    mailQueue,
    serviceConfiguration);

  auto loginRoutes = new LoginRoutes(collection, mailQueue, serviceConfiguration);
  auto userManagement = new UserManagementRoutes(collection, mailQueue, serviceConfiguration);
  auto resourceRoutes = new ResourceRoutes(serviceConfiguration);

  /// Vibe.d router setup
  auto router = new URLRouter();
  router
    .get("*", serveStaticFiles("./public/"))
    .any("*", &resourceRoutes.handler)
    .any("*", &registrationRoutes.handler)
    .any("*", &loginRoutes.handler)
    .any("*", &userManagement.handler)
    .any("*", &handler);

  listenHTTP(settings, router);
}
