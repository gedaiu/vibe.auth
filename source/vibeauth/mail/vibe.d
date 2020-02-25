module vibeauth.mail.vibe;

import vibe.mail.smtp;
import vibe.inet.message;
import vibe.stream.tls;
import vibe.data.json;
import vibe.core.log;

import vibeauth.mail.base;

import vibeauth.data.token;

import std.process;
import std.stdio;
import std.string;
import std.conv;
import std.datetime;

class VibeMailQueue : MailQueue {

	private {
		SMTPClientSettings smtpSettings;
	}

	this(EmailConfiguration settings) {
		super(settings);

		assert(settings.smtp !is null, "The smtp settings are not set");
		smtpSettings = new SMTPClientSettings(settings.smtp.host, settings.smtp.port);
	}

	private auto getSMTPSettings() {
		smtpSettings.host = settings.smtp.host;
		smtpSettings.port = settings.smtp.port;

		smtpSettings.authType = settings.smtp.authType.to!SMTPAuthType;
		smtpSettings.connectionType = settings.smtp.connectionType.to!SMTPConnectionType;
		smtpSettings.tlsValidationMode = settings.smtp.tlsValidationMode.to!TLSPeerValidationMode;
		smtpSettings.tlsVersion = settings.smtp.tlsVersion.to!TLSVersion;

		smtpSettings.localname = settings.smtp.localname;
		smtpSettings.password = settings.smtp.password;
		smtpSettings.username = settings.smtp.username;

		return smtpSettings;
	}

	override void addMessage(Message message) {
		logDebug("Adding a new email to the MailQueue: %s", messages.serializeToJsonString);
		send(message);
	}

	private void send(Message message) {

		foreach(to; message.to) {
			Mail email = new Mail;

			email.headers["Date"] = Clock.currTime.toRFC822DateTimeString;
			email.headers["Sender"] = message.from;
			email.headers["From"] = message.from;
			email.headers["To"] = to;
			email.headers["Subject"] = message.subject;

			foreach(header; message.headers) {
				auto index = header.indexOf(':');
				email.headers[header[0..index]] = header[index+1..$].strip;
			}

			email.bodyText = message.mailBody;

			logDebug("Sending mail: %s", email.serializeToJsonString);

			sendMail(this.getSMTPSettings(), email);
		}
	}
}
