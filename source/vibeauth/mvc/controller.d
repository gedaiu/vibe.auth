module vibeauth.mvc.controller;

import std.string;

import vibeauth.mvc.templatedata;
import vibeauth.configuration;

import std.algorithm;

import vibe.http.router;
import vibe.data.json;

import vibeauth.collections.usercollection;
import vibeauth.error;

/// Generic controller
interface IController {
  /// Returns true if the request can be handled by the controller
  bool canHandle(HTTPServerRequest);

  /// Handle the client request
  void handle(HTTPServerRequest req, HTTPServerResponse res);
}

/// A controller that can handle paths defined in the service configuration
abstract class PathController(string method, string configurationPath) : IController {
  protected {
    UserCollection userCollection;
    ServiceConfiguration configuration;
    string path;
  }

  /// Create the object
  this(UserCollection userCollection, ServiceConfiguration configuration) {
    this.userCollection = userCollection;
    this.configuration = configuration;

    mixin("path = configuration." ~ configurationPath ~ ";");
  }

  /// Returns true if the request and path matches with the template values
  bool canHandle(HTTPServerRequest req) {
    mixin("auto method = HTTPMethod." ~ method ~ ";");
    if(req.method != method) {
      return false;
    }

    if(path.canFind(":id")) {
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
    } else if(path != req.path) {
      return false;
    }


    return true;
  }
}