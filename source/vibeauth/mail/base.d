module vibeauth.mail.base;

import std.string;
import std.random;
import std.array;
import std.algorithm;
import std.conv;

import vibeauth.users;
import vibeauth.token;

struct MailTemplate {
	string subject;

	string text;
	string html;
}

struct EmailConfiguration {
	string from = "noreply@service.com";

	MailTemplate activation =
		MailTemplate("Confirmation instructions",
								"[location][activation]?email=[email]&token=[token]",
								"<a href=\"[location][activation]?email=[email]&token=[token]\">click here</a>");

	MailTemplate resetPassword =
		MailTemplate("Reset password instructions",
								"[location][reset]?email=[email]&token=[token]",
								"<a href=\"[location][reset]?email=[email]&token=[token]\">click here</a>");

	MailTemplate resetPasswordConfirmation =
		MailTemplate("Password changed",
								"Hello, [user.name]!\n\nThe password has successfully been changed.\n\nIf you did not initiate this change, please contact your administrator immediately.",
								"<h1>Hello, [user.name]!</h1><p>The password has successfully been changed.</p><p>If you did not initiate this change, please contact your administrator immediately.</p>");


}

interface IMailSender {
	bool send(Message);
}

interface IMailQueue {
	void addMessage(Message);
	void addActivationMessage(string email, Token token, string[string] variables);
	void addResetPasswordMessage(string email, Token token, string[string] variables);
	void addResetPasswordConfirmationMessage(string email, string[string] variables);
}

struct Message {
	string from;
	string[] to;
	string subject;

	string textMessage;
	string htmlMessage;

	private {
		immutable boundaryCharList = "abcdefghijklmnopqrstuvwxyz0123456789";
		string _boundary;
	}

	string boundary() {
		if(_boundary == "") {
			immutable len = boundaryCharList.length;
			_boundary = "".leftJustify(uniform(20, 30), ' ').map!(a => boundaryCharList[uniform(0, len)]).array;
		}

		return _boundary;
	}

	string[] headers() {
		string[] list;

		if(htmlMessage.length > 0) {
			list ~= "MIME-Version: 1.0";
			list ~= `Content-Type: multipart/alternative; boundary="` ~ boundary ~ `"`;
		}

		return list;
	}

	string mailBody() {
		if(htmlMessage == "") {
			return textMessage;
		}

		string message = "This is a multi-part message in MIME format\r\n\r\n";
		message ~= "--" ~ boundary ~ "\r\n";
		message ~= `Content-Type: text/plain; charset="utf-8"; format="fixed"` ~ "\r\n\r\n";
		message ~= textMessage ~ "\r\n";
		message ~= "--" ~ boundary ~ "\r\n";
		message ~= `Content-Type: text/html; charset="utf-8"` ~ "\r\n\r\n";
		message ~= htmlMessage ~ "\r\n";
		message ~= "--" ~ boundary;

		return message;
	}
}

@("it should add the multipart header if text and html message is present")
unittest {
	auto message = Message();
	message.textMessage = "text";
	message.htmlMessage = "html";

	message.headers[0].should.equal(`MIME-Version: 1.0`);
	message.headers[1].should.equal(`Content-Type: multipart/alternative; boundary="` ~ message.boundary ~ `"`);
}

@("it should not add the multipart header if the html message is missing")
unittest {
	auto message = Message();
	message.textMessage = "text";

	message.headers.length.should.be.equal(0);
}

@("it should generate an unique boundary")
unittest {
	auto message1 = Message();
	auto message2 = Message();

	message1.boundary.should.not.equal("");
	message1.boundary.should.not.be.equal(message2.boundary);
	message1.boundary.should.not.startWith(message2.boundary);
	message2.boundary.should.not.startWith(message1.boundary);
}

@("body should contain only the text message when html is missing")
unittest {
	auto message = Message();
	message.textMessage = "text";

	message.mailBody.should.equal("text");
}

@("body should contain a mime body")
unittest {
	auto message = Message();
	message.textMessage = "text";
	message.htmlMessage = "html";

	string expected = "This is a multi-part message in MIME format\r\n\r\n";
	expected ~= "--" ~ message.boundary ~ "\r\n";
	expected ~= `Content-Type: text/plain; charset="utf-8"; format="fixed"` ~ "\r\n\r\n";
	expected ~= "text\r\n";
	expected ~= "--" ~ message.boundary ~ "\r\n";
	expected ~= `Content-Type: text/html; charset="utf-8"` ~ "\r\n\r\n";
	expected ~= "html\r\n";
	expected ~= "--" ~ message.boundary;

	message.mailBody.should.equal(expected);
}

class MailQueue : IMailQueue {

	protected {
		Message[] messages;
		const EmailConfiguration settings;
	}

	this(const EmailConfiguration settings) {
		this.settings = settings;
	}

	void addMessage(Message message) {
		messages ~= message;
	}

	private void addMessage(MailTemplate mailTemplate, string email, string[string] variables) {
		Message message;

		message.to ~= email;
		message.from = settings.from;
		message.subject = mailTemplate.subject;

		message.textMessage = replaceVariables(mailTemplate.text, variables);
		message.htmlMessage = replaceVariables(mailTemplate.html, variables);

		addMessage(message);
	}

	void addResetPasswordMessage(string email, Token token, string[string] variables) {
		variables["email"] = email;
		variables["token"] = token.name;

		addMessage(settings.resetPassword, email, variables);
	}

	void addActivationMessage(string email, Token token, string[string] variables) {
		variables["email"] = email;
		variables["token"] = token.name;

		addMessage(settings.activation, email, variables);
	}

	void addResetPasswordConfirmationMessage(string email, string[string] variables) {
		variables["email"] = email;

		addMessage(settings.resetPasswordConfirmation, email, variables);
	}

	string replaceVariables(const(string) text, string[string] variables) {
		string data = text.dup;

		foreach(string key, value; variables) {
			data = data.replace("[" ~ key ~ "]", value);
		}

		return data;
	}
}

version(unittest) {
	import bdd.base;

	class MailQueueMock : MailQueue {

		this(EmailConfiguration config) {
			super(config);
		}

		auto lastMessage() {
			return messages[0];
		}
	}
}

@("it should set the text and html activation message")
unittest {
	auto config = EmailConfiguration();
	config.from = "someone@service.com";
	config.activation.subject = "subject";
	config.activation.text = "text";
	config.activation.html = "html";

	auto mailQueue = new MailQueueMock(config);

	string[string] variables;
	mailQueue.addActivationMessage("user@gmail.com", Token(), variables);

	mailQueue.lastMessage.to[0].should.be.equal("user@gmail.com");
	mailQueue.lastMessage.from.should.be.equal("someone@service.com");
	mailQueue.lastMessage.subject.should.be.equal("subject");
	mailQueue.lastMessage.textMessage.should.be.equal("text");
	mailQueue.lastMessage.htmlMessage.should.be.equal("html");
}

@("it should set the text and html reset password message")
unittest {
	auto config = EmailConfiguration();
	config.from = "someone@service.com";
	config.resetPassword.subject = "subject";
	config.resetPassword.text = "text";
	config.resetPassword.html = "html";

	auto mailQueue = new MailQueueMock(config);

	string[string] variables;
	mailQueue.addResetPasswordMessage("user@gmail.com", Token(), variables);

	mailQueue.lastMessage.to[0].should.be.equal("user@gmail.com");
	mailQueue.lastMessage.from.should.be.equal("someone@service.com");
	mailQueue.lastMessage.subject.should.be.equal("subject");
	mailQueue.lastMessage.textMessage.should.be.equal("text");
	mailQueue.lastMessage.htmlMessage.should.be.equal("html");
}
