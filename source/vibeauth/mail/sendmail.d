module vibeauth.mail.sendmail;

import vibeauth.mail.base;
import vibeauth.users;
import vibeauth.token;

import std.process;
import std.stdio;

class SendMailQueue : MailQueue {

	this(RegistrationConfigurationEmail settings) {
		super(settings);
	}

	override void addMessage(Message message) {
		send(message);
	}

	private void send(Message message) {

		foreach(to; message.to) {
			// sendmail expects to read from stdin
			auto pipes = pipeProcess(["sendmail", "-t"], Redirect.stdin);
			pipes.stdin.write("To: " ~ to ~ "\r\n");
			pipes.stdin.write("From: " ~ message.from ~ "\r\n");
			pipes.stdin.write("Subject: " ~ message.subject ~ "\r\n");
			pipes.stdin.write("\r\n");
			pipes.stdin.write(message.textMessage ~ "\r\n");

			// a single period tells sendmail we are finished
			pipes.stdin.write(".\r\n");

			// but at this point sendmail might not see it, we need to flush
			pipes.stdin.flush();

			// sendmail happens to exit on ".", but some you have to close the file:
			pipes.stdin.close();

			// otherwise this wait will wait forever
			wait(pipes.pid);
		}
	}
}
