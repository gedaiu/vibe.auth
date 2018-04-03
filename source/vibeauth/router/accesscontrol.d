module vibeauth.router.accesscontrol;

import vibe.http.router;
import std.string;
import std.algorithm;

void addHeaderValue(ref HTTPServerResponse res, string name, string[] values) {
  if(name in res.headers) {
    values = res.headers[name].split(",") ~ values;
  }

  res.headers[name] = values.map!(a => a.strip).uniq.filter!(a => a != "").join(", ");
}

void setAccessControl(ref HTTPServerResponse res) {
  res.addHeaderValue("Access-Control-Allow-Origin", ["*"]);
  res.addHeaderValue("Access-Control-Allow-Headers", ["Authorization"]);
}
