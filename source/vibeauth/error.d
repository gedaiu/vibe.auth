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
