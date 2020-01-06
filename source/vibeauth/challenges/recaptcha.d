
module vibeauth.challenges.recaptcha;

import vibe.http.client;
import vibe.stream.operations;
import vibe.data.json;
import vibe.core.log;

import std.conv;

import vibeauth.challenges.base;

interface IReCaptchaConfig {
  string siteKey();
  string secretKey();
}

/// Class that implements the google recaptcha challenge
class ReCaptcha : IChallenge {

  private {
    IReCaptchaConfig config;
  }

  this(IReCaptchaConfig config) {
    this.config = config;
  }

  /// Generate a challenge. The request must be initiated from the challenge template
  string generate(HTTPServerRequest req, HTTPServerResponse res) {
    return "";
  }

  /// Get a template for the current challenge
  string getTemplate(string challangeLocation) {
    auto tpl = `<script src="https://www.google.com/recaptcha/api.js?render=` ~ config.siteKey ~ `"></script>
      <script>
      grecaptcha.ready(function() {
          grecaptcha.execute('` ~ config.siteKey ~ `', {action: 'login'}).then(function(token) {
            document.querySelector("#recaptchaValue").value = token;
          });
      });
      </script>
      <input id="recaptchaValue" name="response" type="hidden" value="">`;

    return tpl;
  }

  /// Returns the site key
  Json getConfig() {
    auto result = Json.emptyObject;

    result["siteKey"] = config.siteKey;

    return result;
  }

  /// Validate the challenge
  bool validate(string response) {
    logInfo("Validating the recaptcha response: %s", response);

    try {
      Json result;
      auto link = "https://www.google.com/recaptcha/api/siteverify?secret=" ~ config.secretKey ~ "&response=" ~ response;
      logDebug("Sending request to %s", link);

      requestHTTP(link,
        (scope req) {
          req.method = HTTPMethod.POST;
          req.headers["Content-length"] = "0";
        },
        (scope res) {
          logInfo("Recaptcha server response: %s %s", res.statusPhrase, res.statusCode);
          result = res.bodyReader.readAllUTF8().parseJsonString;

          logInfo("Recaptcha server response message: %s", result);
        }
      );

      if("success" !in result) {
        return false;
      }

      return result["success"].to!bool == true;
    } catch(Exception e) {
      logError("Error sending the recaptcha request: %s", e.message);
    }

    return true;
  }
}
