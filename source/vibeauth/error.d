/++
  A module containing exceptions thrown by this library

  Copyright: © 2018 Szabo Bogdan
  License: Subject to the terms of the MIT license, as written in the included LICENSE.txt file.
  Authors: Szabo Bogdan
+/

module vibeauth.error;

/// Exception thrown when an access level does not exist
class UserAccesNotFoundException : Exception {

  /// Create the exception
  this(string msg = null, Throwable next = null) { super(msg, next); }

  /// dutto
  this(string msg, string file, size_t line, Throwable next = null) {
    super(msg, file, line, next);
  }
}

/// Exception thrown when an item does not exist
class ItemNotFoundException : Exception {
  this(string msg = null, Throwable next = null) { super(msg, next); }
  this(string msg, string file, size_t line, Throwable next = null) {
    super(msg, file, line, next);
  }
}

/// Exception thrown when an user does not exist
class UserNotFoundException : ItemNotFoundException {
  this(string msg = null, Throwable next = null) { super(msg, next); }
  this(string msg, string file, size_t line, Throwable next = null) {
    super(msg, file, line, next);
  }
}

version(unittest) {
  import fluent.asserts;
}

@("UserNotFoundException is an ItemNotFoundException")
unittest {
  try {
    throw new UserNotFoundException("not found");
  } catch (ItemNotFoundException e) {
    e.msg.should.equal("not found");
  }
}

@("exception message propagates correctly")
unittest {
  auto e = new UserAccesNotFoundException("bad access");
  e.msg.should.equal("bad access");
}
