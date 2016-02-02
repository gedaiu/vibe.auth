module vibeauth.client;

import vibe.data.json;

import std.stdio;
import std.algorithm.searching;
import std.algorithm.iteration;
import std.exception;
import std.uuid;
import std.conv;
import std.datetime;

class ClientNotFoundException : Exception {
  this(string msg = null, Throwable next = null) { super(msg, next); }
  this(string msg, string file, size_t line, Throwable next = null) {
    super(msg, file, line, next);
  }
}

class Client {
  string id;
  string name;
  string description;
  string website;
}

class ClientCollection : Collection!Client {

}
