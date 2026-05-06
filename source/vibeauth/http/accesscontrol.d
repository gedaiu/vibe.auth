module vibeauth.http.accesscontrol;

import vibe.http.router;
import std.string;
import std.algorithm;

/// Add a value to an existing header
void addHeaderValue(ref HTTPServerResponse res, string name, string[] values) {
  if(name in res.headers) {
    values = res.headers[name].split(",") ~ values;
  }

  res.headers[name] = values.map!(a => a.strip).uniq.filter!(a => a != "").join(", ");
}

/// Add the CORS headers
void setAccessControl(ref HTTPServerResponse res) {
  res.addHeaderValue("Access-Control-Allow-Origin", ["*"]);
  res.addHeaderValue("Access-Control-Allow-Headers", ["Authorization", "Content-Type"]);
  res.addHeaderValue("Access-Control-Allow-Methods", ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]);
}

/// Predicate that decides whether an incoming `Origin` is allowed to make
/// credentialed cross-origin requests. Pluggable so consumers can back it with
/// a static list, a DB lookup, a cache, etc.
alias OriginPredicate = bool delegate(string origin);

/// Add CORS headers, echoing the request `Origin` and enabling credentials when
/// `isCredentialedOrigin` accepts it. Required when the response sets cookies
/// that the browser is expected to send back on subsequent cross-origin
/// requests: browsers reject `Set-Cookie` paired with
/// `Access-Control-Allow-Origin: *`, and reject responses to credentialed XHRs
/// that don't echo the exact origin. Falls back to wildcard `setAccessControl`
/// when the predicate is null or rejects the origin, so non-credentialed
/// clients keep working unchanged.
void setAccessControl(HTTPServerRequest req, ref HTTPServerResponse res, OriginPredicate isCredentialedOrigin) {
  if(isCredentialedOrigin is null || "Origin" !in req.headers) {
    setAccessControl(res);
    return;
  }

  auto origin = req.headers["Origin"];
  if(!isCredentialedOrigin(origin)) {
    setAccessControl(res);
    return;
  }

  res.headers["Access-Control-Allow-Origin"] = origin;
  res.headers["Access-Control-Allow-Credentials"] = "true";
  res.addHeaderValue("Vary", ["Origin"]);
  res.addHeaderValue("Access-Control-Allow-Headers", ["Authorization", "Content-Type"]);
  res.addHeaderValue("Access-Control-Allow-Methods", ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]);
}
