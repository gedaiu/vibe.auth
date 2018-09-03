module vibeauth.router.resources.routes;

import std.socket;
import std.net.curl;
import std.file;
import std.path;
import std.digest.md;
import std.algorithm;
import std.algorithm.mutation : copy;

import core.time;

import vibe.core.log;
import vibe.core.file;
import vibe.http.server;
import vibe.stream.operations;
import vibeauth.configuration;

version(unittest) {
  import vibe.http.router;
  import fluentasserts.vibe.request;
  import fluentasserts.vibe.json;
  import fluent.asserts;
}

enum bootstrapStyleUrl = "https://stackpath.bootstrapcdn.com/bootstrap/4.1.3/css/bootstrap.min.css";
enum localBootstrapStyle = "tmp/assets/bootstrap.min.css";

enum bootstrapJsUrl = "https://stackpath.bootstrapcdn.com/bootstrap/4.1.3/js/bootstrap.bundle.min.js";
enum localBootstrapJs = "tmp/assets/bootstrap.min.js";

enum jqueryUrl = "https://code.jquery.com/jquery-3.3.1.slim.min.js";
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

  version(unittest) {
    std.file.write("tmp/test.css", "data");
    std.file.write("tmp/test.js", "data");
  }
}

/// Static resource
struct Resource(string path) {
  static immutable {
    string etag;
    string data;
    string mime;
  }

  ///
  static this() {
    auto ctx = makeDigest!MD5();

    data = readText(path);
    copy(data, &ctx); //Note: You must pass a pointer to copy!
    etag = ctx.finish().toHexString.idup;

    if(path.endsWith(".css")) {
      mime = "text/css";
    }

    if(path.endsWith(".js")) {
      mime = "text/javascript";
    }
  }

  ///
  void handler(HTTPServerRequest req, HTTPServerResponse res) {
    res.headers["Cache-Control"] = "max-age=86400";
    res.headers["ETag"] = etag;

    if("If-None-Match" in req.headers && req.headers["If-None-Match"] == etag) {
      res.statusCode = 304;
      res.writeVoidBody;
      return;
    }

    res.statusCode = 200;
    res.writeBody(data, mime);
  }
}

/// It should store the the valid properties
unittest {
  Resource!"tmp/test.css" resource;
  resource.data.should.equal("data");
  resource.mime.should.equal("text/css");
  resource.etag.should.equal("8D777F385D3DFEC8815D20F7496026DC");

  Resource!"tmp/test.js" resourceJs;
  resourceJs.mime.should.equal("text/javascript");
}

/// It should get a resource with the right headers
unittest {
  Resource!"tmp/test.css" resource;

  auto router = new URLRouter();
  router.get("/resource", &resource.handler);

  router
    .request
    .get("/resource")
    .expectHeader("ETag", resource.etag)
    .expectHeader("Content-Type", "text/css")
    .expectStatusCode(200)
    .end((Response response) => {
      response.bodyString.should.equal("data");
    });
}

/// It should not get a resource with the etag matches
unittest {
  Resource!"tmp/test.css" resource;

  auto router = new URLRouter();
  router.get("/resource", &resource.handler);

  router
    .request
    .get("/resource")
    .header("If-None-Match", resource.etag)
    .expectHeader("ETag", resource.etag)
    .expectStatusCode(304)
    .end((Response response) => {
      response.bodyString.should.equal("");
    });
}

/// Handle resources served by vibe auth
class ResourceRoutes {

  private {
    const {
      ServiceConfiguration configuration;
    }

    Resource!localBootstrapStyle _bootstrapStyle;
    Resource!localBootstrapJs _bootstrapJs;
    Resource!localJquery _jquery;
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
      _bootstrapStyle.handler(req, res);
    }

    if(req.method == HTTPMethod.GET && req.path == configuration.paths.resources.bootstrapJs) {
      _bootstrapJs.handler(req, res);
    }

    if(req.method == HTTPMethod.GET && req.path == configuration.paths.resources.jquery) {
      _jquery.handler(req, res);
    }
  }
}

