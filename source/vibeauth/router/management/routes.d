/++
  A module that handles the user management. It binds the routes, renders the templates and
  updates the collections.

  Copyright: © 2018 Szabo Bogdan
  License: Subject to the terms of the MIT license, as written in the included LICENSE.txt file.
  Authors: Szabo Bogdan
+/
module vibeauth.router.management.routes;

import vibe.http.router;
import vibe.data.json;

import vibeauth.data.user;
import vibeauth.collections.usercollection;
import vibeauth.configuration;
import vibeauth.mail.base;
import vibeauth.router.management.responses;
import vibeauth.mvc.view;
import vibeauth.mvc.controller;

import std.string;
import std.algorithm;
import std.conv;
import std.regex;

/// It handles vibe.d requests
class UserManagementRoutes {
  private {
    UserCollection userCollection;
    ServiceConfiguration configuration;

    IMailQueue mailQueue;

    IController[] controllers;
  }

  /// Initalize the object
  this(UserCollection userCollection, IMailQueue mailQueue, ServiceConfiguration configuration = ServiceConfiguration.init) {
    this.configuration = configuration;
    this.userCollection = userCollection;
    this.mailQueue = mailQueue;

    controllers = cast(IController[]) [
      new ListController(userCollection, configuration),

      new ProfileController(userCollection, configuration),
      new UpdateProfileController(userCollection, configuration),

      new AccountController(userCollection, configuration),
      new UpdateAccountController(userCollection, configuration),

      new DeleteAccountController(userCollection, configuration),

      new SecurityController(userCollection, configuration),
      new RevokeAdminController(userCollection, configuration),
      new MakeAdminController(userCollection, configuration)
    ];
  }

  /// Generic handler for all user management routes
  void handler(HTTPServerRequest req, HTTPServerResponse res) {
    foreach(controller; controllers) {
      if(controller.canHandle(req)) {
        controller.handle(req, res);
        return;
      }
    }
  }
}
