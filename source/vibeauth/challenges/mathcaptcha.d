module vibeauth.challenges.mathcaptcha;

import vibeauth.challenges.base;
import vibeauth.challenges.imagegenerator;

import std.datetime;
import std.uuid;
import std.conv;
import std.string;
import std.random;
import std.stdio;

import vibe.stream.memory;
import vibe.stream.wrapper;
import diet.html;

struct MathCaptchaSettings {
  string bgColor = "white";
  string textColor = "black";
  long fontSize = 15;
  string fontName = "sans-serif";

  size_t maxWidth = 350;
  size_t maxHeight = 100;
}

class MathCaptcha : IChallenge {
  private static {
    MathCaptchaSettings settings;
    CodeEntry[string] codes;
  }

  this(MathCaptchaSettings settings) {
    this.settings = settings;
  }

  string generate(HTTPServerRequest req, HTTPServerResponse res) {
    clearExpired();
    auto generator = ImageGenerator(settings.maxWidth, settings.maxHeight, settings.bgColor);

    auto number = uniform(0, 100);
    auto result = number;

    string question = number.to!string;
    uint sign = 0;

    if(uniform(0, 2) == 0) {
      question ~= "+";
      sign = 1;
    } else {
      question ~= "-";
      sign = -1;
    }

    number = uniform(0, 100);
    result += number * sign;

    question ~= number.to!string ~ "=";

    generator.setTextColor(settings.textColor);
    generator.setFontSize(settings.fontSize);
    generator.setFontName(settings.fontName);
    generator.setText(question);

    string key;

    if("mathcaptcha" !in req.cookies) {
      key = randomUUID.toString;
    } else {
      key = req.cookies["mathcaptcha"];
    }

    codes[key] = CodeEntry(Clock.currTime + 120.seconds, result.to!string);
    res.setCookie("mathcaptcha", key);
    res.cookies["mathcaptcha"].maxAge = 120;

    generator.flush(res);
    return result.to!string;
  }

  bool validate(HTTPServerRequest req, HTTPServerResponse res, string response) {
    clearExpired();

    if("mathcaptcha" !in req.cookies) {
      return false;
    }

    auto key = req.cookies["mathcaptcha"];

    if(key !in codes) {
      return false;
    }

    auto expected = codes[key].result;

    codes.remove(key);
    res.setCookie("mathcaptcha", null);

    return response == expected;
  }

  void clearExpired() {
    string[] keys;

    foreach(string key, value; codes) {
      if(value.time < Clock.currTime) {
        keys ~= key;
      }
    }

    foreach(key; keys) {
      codes.remove(key);
    }
  }

  string getTemplate(string challangeLocation) {
    import std.array : appender;
    auto output = appender!string();

    output
      .compileHTMLDietFile!("challanges/math.dt", challangeLocation);

    return output.data;
  }
}
