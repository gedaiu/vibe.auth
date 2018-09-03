
module vibeauth.challenges.recaptcha;

import vibe.http.client;
import vibe.stream.operations;
import vibe.data.json;

import std.conv;

import vibeauth.challenges.base;

/// Class that implements the google recaptcha challenge
class ReCaptcha : IChallenge {

  private immutable {
    string siteKey;
    string secretKey;
  }

  this(string siteKey, string secretKey) {
    this.siteKey = siteKey;
    this.secretKey = secretKey;
  }

  /// Generate a challenge. The request must be initiated from the challenge template
  string generate(HTTPServerRequest req, HTTPServerResponse res) {
    return "";
  }

  /// Get a template for the current challenge
  string getTemplate(string challangeLocation) {
    auto tpl = `<script src="https://www.google.com/recaptcha/api.js?render=` ~ siteKey ~ `"></script>
      <script>
      grecaptcha.ready(function() {
          grecaptcha.execute('` ~ siteKey ~ `', {action: 'login'}).then(function(token) {
            document.querySelector("#recaptchaValue").value = token;
          });
      });
      </script>
      <input id="recaptchaValue" name="response" type="hidden" value="">`;

    return tpl;
  }

  /// Validate the challenge
  bool validate(HTTPServerRequest req, HTTPServerResponse res, string response) {
    import std.stdio;
    writeln("response:", response);
    Json result;

    requestHTTP("https://www.google.com/recaptcha/api/siteverify?secret=" ~ secretKey ~ "&response=" ~ response,
      (scope req) {
        req.method = HTTPMethod.POST;
        req.headers["Content-length"] = "0";
      },
      (scope res) {
        result = res.bodyReader.readAllUTF8().parseJsonString;
      }
    );


    writeln(result);

    if("success" !in result) {
      return false;
    }

    writeln(result["success"].to!bool == true);

    return result["success"].to!bool == true;
  }
}