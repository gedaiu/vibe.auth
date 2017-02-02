module vibeauth.mail.base;

import std.string;

import vibeauth.users;
import vibeauth.token;

struct RegistrationConfigurationEmail {
	string from = "noreply@service.com";
	string confirmationSubject = "Confirmation instructions";
	string confirmationText = "[confirmationLink]";
	string confirmationHtml = "<a href=\"[confirmationLink]\">click here</a>";
}

interface IMailSender {
	bool send(Message);
}

interface IMailQueue {
	void addMessage(Message);
	void addActivationMessage(UserData data, Token token);
}

struct Message {
	string from;
	string[] to;
	string subject;

	string textMessage;
	string htmlMessage;
}

class MailQueue : IMailQueue {

	protected {
		Message[] messages;
		const RegistrationConfigurationEmail settings;
	}

	this(const RegistrationConfigurationEmail settings) {
		this.settings = settings;
	}

	void addMessage(Message message) {
		messages ~= message;
	}

	void addActivationMessage(UserData data, Token token) {
		Message message;

		string link = "http://localhost/register/activation?email=" ~ data.email ~ "&token=" ~ token.name;

		message.to ~= data.email;
		message.from = settings.from;
		message.subject = settings.confirmationSubject;
		message.textMessage = settings.confirmationText.dup.replace("[confirmationLink]", link);
		message.htmlMessage = settings.confirmationHtml.dup.replace("[confirmationLink]", link);

		addMessage(message);
	}
}

version(unittest) {
	import bdd.base;

	class MailQueueMock : MailQueue {

		this(RegistrationConfigurationEmail config) {
			super(config);
		}

		auto lastMessage() {
			return messages[0];
		}
	}
}

@("it should set the text and html activation message")
unittest {
	auto config = RegistrationConfigurationEmail();
	config.from = "someone@service.com";
	config.confirmationSubject = "subject";
	config.confirmationText = "text";
	config.confirmationHtml = "html";

	auto mailQueue = new MailQueueMock(config);
	auto user = UserData();
	user.email = "user@gmail.com";
	mailQueue.addActivationMessage(user, Token());

	mailQueue.lastMessage.to[0].should.be.equal("user@gmail.com");
	mailQueue.lastMessage.from.should.be.equal("someone@service.com");
	mailQueue.lastMessage.subject.should.be.equal("subject");
	mailQueue.lastMessage.textMessage.should.be.equal("text");
	mailQueue.lastMessage.htmlMessage.should.be.equal("html");
}
