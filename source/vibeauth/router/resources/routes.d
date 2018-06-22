module vibeauth.router.resources.routes;

import std.socket;
import std.net.curl;
import std.file;
import std.path;
import std.digest.md;
import std.algorithm.mutation : copy;

import core.time;

import vibe.core.log;
import vibe.core.file;
import vibe.http.server;
import vibe.stream.operations;
import vibeauth.configuration;

enum bootstrapStyleUrl = "https://maxcdn.bootstrapcdn.com/bootstrap/4.1.1/css/bootstrap.min.css";
enum localBootstrapStyle = "tmp/assets/bootstrap.min.css";

enum bootstrapJsUrl = "https://maxcdn.bootstrapcdn.com/bootstrap/4.1.1/js/bootstrap.min.js";
enum localBootstrapJs = "tmp/assets/bootstrap.min.js";

enum jqueryUrl = "https://code.jquery.com/jquery-3.2.1.slim.min.js";
enum localJquery = "tmp/assets/jquery.min.js";

shared static this() {
  if(!localBootstrapStyle.exists) {
    mkdirRecurse(localBootstrapStyle.dirName);
    download(bootstrapStyleUrl, localBootstrapStyle);
  }


  if(!localBootstrapJs.exists) {
    mkdirRecurse(localBootstrapJs.dirName);
    download(bootstrapJsUrl, localBootstrapJs);
  }

  if(!localJquery.exists) {
    mkdirRecurse(localJquery.dirName);
    download(jqueryUrl, localJquery);
  }
}

struct Resource(string path) {
  static immutable {
    string etag;
    string data;
  }

  static this() {
    auto ctx = makeDigest!MD5();

    data = readText(path);
    copy(data, &ctx); //Note: You must pass a pointer to copy!
    etag = ctx.finish().toHexString.idup;
  }
}

/// Handle the registration routes
class ResourceRoutes {

  private {
    const {
      ServiceConfiguration configuration;
    }

    immutable {
      Resource!localBootstrapStyle _bootstrapStyle;
      Resource!localBootstrapJs _bootstrapJs;
      Resource!localJquery _jquery;
    }
  }

  ///
  this(const ServiceConfiguration configuration) {
    this.configuration = configuration;
    _bootstrapStyle = Resource!localBootstrapStyle();
    _bootstrapJs = Resource!localBootstrapJs();
    _jquery = Resource!localJquery();
  }

  /// Handle the requests
  void handler(HTTPServerRequest req, HTTPServerResponse res) {
    if(req.method == HTTPMethod.GET && req.path == configuration.paths.resources.bootstrapStyle) {
      bootstrapStyle(req, res);
    }

    if(req.method == HTTPMethod.GET && req.path == configuration.paths.resources.bootstrapJs) {
      bootstrapJs(req, res);
    }

    if(req.method == HTTPMethod.GET && req.path == configuration.paths.resources.jquery) {
      jquery(req, res);
    }
  }

  void bootstrapStyle(HTTPServerRequest req, HTTPServerResponse response) {
    if("If-None-Match" in req.headers && req.headers["If-None-Match"] == _bootstrapStyle.etag) {
      response.statusCode = 304;
      response.writeVoidBody;
      return;
    }

    response.headers["Cache-Control"] = "max-age=3600";
    response.headers["ETag"] = _bootstrapStyle.etag;
    response.writeBody(_bootstrapStyle.data, "text/css");
  }

  void bootstrapJs(HTTPServerRequest req, HTTPServerResponse response) {
    if("If-None-Match" in req.headers && req.headers["If-None-Match"] == _bootstrapJs.etag) {
      response.statusCode = 304;
      response.writeVoidBody;
      return;
    }

    response.headers["Cache-Control"] = "max-age=3600";
    response.headers["ETag"] = _bootstrapJs.etag;
    response.writeBody(_bootstrapJs.data, "text/javascript");
  }

  void jquery(HTTPServerRequest req, HTTPServerResponse response) {
    if("If-None-Match" in req.headers && req.headers["If-None-Match"] == _jquery.etag) {
      response.statusCode = 304;
      response.writeVoidBody;
      return;
    }

    response.headers["Cache-Control"] = "max-age=3600";
    response.headers["ETag"] = _jquery.etag;
    response.writeBody(_jquery.data, "text/javascript");
  }
}

