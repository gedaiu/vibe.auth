module vibeauth.mvc.view;

import std.string;

import vibeauth.mvc.templatedata;
import vibeauth.configuration;

import vibe.data.json;

/// Default view
class View {
  protected {
    const string stringTemplate;
  }

  /// Data that will be used in the template
  TemplateData data;

  ///
  alias data this;

  /// Create the template
  this(const string stringTemplate) {
    this.stringTemplate = stringTemplate;
  }

  /// ditto
  this(const string stringTemplate, Json defaultOptions) {
    this.stringTemplate = stringTemplate;
    data.add(defaultOptions);
  }

  /// Generates an empty body. If #{body} variable is present, it will be removed
  string generateBody() {
    return "";
  }

  /// Replace all the variables with the provided options
  string render() {
    return data.render(stringTemplate.replace("#{body}", generateBody()));
  }
}

/// View that will use a configured templates
class BasicView(string tplProperty, string bodyProperty) : View {
  private {
    const ServiceConfiguration configuration;
  }

  /// 
  this(const ServiceConfiguration configuration) {
    this.configuration = configuration;

    mixin(`super(configuration.` ~ tplProperty ~ `, configuration.serializeToJson);`);
  }

  ///
  override string generateBody() {
    mixin(`return configuration.` ~ bodyProperty ~ `;`);
  }
}
