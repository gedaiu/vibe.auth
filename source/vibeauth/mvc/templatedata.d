/++
  A module containing helper functions to ease the template usage

  Copyright: © 2018 Szabo Bogdan
  License: Subject to the terms of the MIT license, as written in the included LICENSE.txt file.
  Authors: Szabo Bogdan
+/
module vibeauth.mvc.templatedata;

import std.string;
import std.algorithm;
import std.conv;
import std.stdio;

import vibe.data.json;


version(unittest) {
  import fluent.asserts;
}

/// Structure used to store the data that will rendered inside a template
struct TemplateData {
  private {
    Json[] options;
    string[string] variables;
    string[] messages;
    string[] errors;
  }

  /***************************************************************************************************

    Adds a set of options. The strings that will match these options will be replaced in the rendered
    string.

    eg. for this data set:

    {
      "key": "value"
      "level1": {
        "key": "value"
      }
    }

    #{key} and #{level1.key} will be replaced

  ***************************************************************************************************/
  void add(Json options) {
    this.options ~= options;
  }

  /// ditto
  void add(string key, Json options) {
    Json obj = Json.emptyObject;
    obj[key] = options;

    this.options ~= obj;
  }

  /// ditto
  void add(string key, string value) {
    Json obj = Json.emptyObject;
    obj[key] = value;

    this.options ~= obj;
  }

  /// Add a notification to the user
  void addMessage(string message) {
    messages ~= message;
  }

  /// Add an error to the user
  void addError(string error) {
    errors ~= error;
  }


  /***************************************************************************************************

    Set a variable that will be replaced inside the options.

    eg. for this data set:

    {
      "key": "value :id"
      "level1": {
        "key": "value :id"
      }
    }

    after set(":id", "/user/:id", "/user/3")

    the options will be:
    {
      "key": "value 3"
      "level1": {
        "key": "value 3"
      }
    }

  ***************************************************************************************************/
  void set(string variable, string route, string path) {
    auto pathValue = getValue(variable, route, path);
    variables[variable] = pathValue;
  }

  ///
  private void replaceJson(ref Json json, string variable, string value) {
    if(json.type == Json.Type.string) {
      json = json.to!string.replace(variable, value);
    }

    if(json.type == Json.Type.object) {
      foreach(string key, ref jsonValue; json) {
        replaceJson(jsonValue, variable, value);
      }
    }
  }

  /// Get a variable
  string get(string variable) {
    return variables[variable];
  }

  /// Render a template
  string render(string page) {
    foreach(key, value; variables) {
      foreach(ref item; options) {
        replaceJson(item, key, value);
      }
    }

    foreach(item; options) {
      page = page.replaceVariables(item);
    }

    page = page.replace("#{messages}", renderErrors ~ renderMessages);

    return page;
  }

  private string renderMessages() {
    return messages.map!(a => `<div class="alert alert-info alert-dismissible fade show" role="alert">
      ` ~ a ~ `
      <button type="button" class="close" data-dismiss="alert" aria-label="Close">
        <span aria-hidden="true">&times;</span>
      </button>
    </div>`).join;
  }

  private string renderErrors() {
    return errors.map!(a => `<div class="alert alert-danger alert-dismissible fade show" role="alert">
      ` ~ a ~ `
      <button type="button" class="close" data-dismiss="alert" aria-label="Close">
        <span aria-hidden="true">&times;</span>
      </button>
    </div>`).join;
  }
}

/// Eschape html special chars: & " ' < >
string escapeHtmlString(string data) {
  return data
    .replace("&", "&amp;")
    .replace("\"", "&quot;")
    .replace("'", "&#039;")
    .replace("<", "&lt;")
    .replace(">", "&gt;");
}

/// escape html strings
unittest {
  "&\"'<>".escapeHtmlString.should.equal("&amp;&quot;&#039;&lt;&gt;");
}

/// Return true if the route path matches listpath/:id
string getValue(string variable, string routePath, string path) {
  auto pieces = routePath.split(variable);
  auto routePieces = path.split("/");

  if(!routePath.startsWith(pieces[0]) || !routePath.endsWith(pieces[1])) {
    return "";
  }

  auto prefixLen = pieces[0].length;
  auto postfixLen = pieces[1].length;

  if(path.length < prefixLen) {
    return "";
  }

  if(routePath[prefixLen .. $-postfixLen].canFind("/")) {
    return "";
  }

  return path[prefixLen .. $-postfixLen];
}

/// getValue usage
unittest {
  getValue(":id", "/users/:id", "/users/some page").should.equal("some page");
  getValue(":id", "/users/:id", "/users").should.equal("");
}

/// Search variables `#{variable_name}` and replace them with the values from json
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

/// replace variables
unittest {
  Json data = Json.emptyObject;
  data["one"] = "1";
  data["second"] = Json.emptyObject;
  data["second"]["value"] = "2";

  "#{one}-#{second.value}".replaceVariables(data).should.startWith("1-");
  "#{one}-#{second.value}".replaceVariables(data).should.endWith("-2");
}


/// should not replace variables on undefined data
unittest {
  Json data;

  "#{one}-#{second.value}".replaceVariables(data).should.startWith("#{one}-");
  "#{one}-#{second.value}".replaceVariables(data).should.endWith("-#{second.value}");
}


/// Return true if the route path matches listpath/:id
bool isUserPage(string routePath, string path) {
  auto pieces = routePath.split(":id");

  if(!path.startsWith(pieces[0]) || !path.endsWith(pieces[1])) {
    return false;
  }

  auto prefixLen = pieces[0].length;
  auto postfixLen = pieces[1].length;

  if(path[prefixLen .. $-postfixLen].canFind("/")) {
    return false;
  }

  return true;
}

/// isUserPage tests
unittest {
  isUserPage("/users/:id", "/users/some page").should.equal(true);
  isUserPage("/users/:id", "/users").should.equal(false);
  isUserPage("/users/:id", "/other/some").should.equal(false);
  isUserPage("/users/:id", "/other").should.equal(false);
}
