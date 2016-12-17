module vibeauth.token;

import std.datetime;

struct Token {
  string name;
  SysTime expire;
  string[] scopes;
  string type = "Bearer";
}
