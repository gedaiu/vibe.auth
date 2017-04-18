module vibeauth.templatehelper;

import std.conv;
import std.stdio;
import std.string;
import vibe.data.json;

string replaceVariables(const string data, const Json variables, const string prefix = "") {
  string result = data.dup;

  if(variables.type == Json.Type.object) {
    foreach(string key, value; variables) {

      if(value.type == Json.Type.object) {
        result = result.replaceVariables(value, prefix ~ key ~ ".");
      } else {
        result = result.replace("#{" ~ prefix ~ key ~ "}", value.to!string);
      }
    }
  }

  return result;
}

version(unittest) {
  import fluent.asserts;
}

@("replace variables")
unittest {
  Json data = Json.emptyObject;
  data["one"] = "1";
  data["second"] = Json.emptyObject;
  data["second"]["value"] = "2";

  "#{one}-#{second.value}".replaceVariables(data).should.startWith("1-");
  "#{one}-#{second.value}".replaceVariables(data).should.endWith("-2");
}


@("should not replace variables on undefined data")
unittest {
  Json data;

  "#{one}-#{second.value}".replaceVariables(data).should.startWith("#{one}-");
  "#{one}-#{second.value}".replaceVariables(data).should.endWith("-#{second.value}");
}
