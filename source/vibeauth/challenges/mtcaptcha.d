module vibeauth.challenges.mtcaptcha;

import vibe.http.client;
import vibe.stream.operations;
import vibe.data.json;
import vibe.core.log;

import std.conv;

import vibeauth.challenges.base;

interface IMtCaptchaConfig {
  string siteKey();
  string privateKey();
}

/// Class that implements the google recaptcha challenge
class MtCaptcha : IChallenge {

  private {
    IMtCaptchaConfig config;
  }

  this(IMtCaptchaConfig config) {
    this.config = config;
  }

  /// Generate a challenge. The request must be initiated from the challenge template
  string generate(HTTPServerRequest req, HTTPServerResponse res) {
    return "";
  }

  /// Get a template for the current challenge
  string getTemplate(string challangeLocation) {
    return "";
  }

  /// Returns the site key
  Json getConfig() {
    auto result = Json.emptyObject;

    result["siteKey"] = config.siteKey;

    return result;
  }

  /// Validate the challenge
  bool validate(string response) {
    logInfo("Validating the mtCAPTCHA response: %s", response);

    try {
      Json result;
      auto link = "https://service.mtcaptcha.com/mtcv1/api/checktoken?privatekey=" ~
        config.privateKey ~ "&token=" ~ response;

      logInfo("Sending request to %s", link);

      requestHTTP(link,
        (scope req) {
          req.method = HTTPMethod.GET;
        },
        (scope res) {
          logInfo("mtCAPTCHA server response: %s %s", res.statusPhrase, res.statusCode);
          result = res.bodyReader.readAllUTF8().parseJsonString;

          logInfo("mtCAPTCHA server response message: %s", result);
        }
      );

      if("success" !in result) {
        return false;
      }

      return result["success"].to!bool == true;
    } catch(Exception e) {
      logError("Error sending the mtCAPTCHA request: %s", e.message);
    }

    return true;
  }
}

version(unittest) {
  import fluent.asserts;

  class TestMtCaptchaConfig : IMtCaptchaConfig {
    string siteKey() { return "mt-site-key"; }
    string privateKey() { return "mt-private-key"; }
  }
}

@("getConfig returns JSON with siteKey")
unittest {
  auto captcha = new MtCaptcha(new TestMtCaptchaConfig());
  auto config = captcha.getConfig();

  config["siteKey"].get!string.should.equal("mt-site-key");
}

@("getTemplate returns empty string")
unittest {
  auto captcha = new MtCaptcha(new TestMtCaptchaConfig());
  captcha.getTemplate("/challenge").should.equal("");
}
