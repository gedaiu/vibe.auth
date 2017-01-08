module vibeauth.mail.base;

import vibeauth.users;
import vibeauth.token;

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

class MailQueue {

  private Message[] messages;

  void addMessage(Message message) {
    messages ~= message;
  }

  void addActivationMessage(UserData data, Token token) {
    Message message;

    addMessage(message);
  }
}
