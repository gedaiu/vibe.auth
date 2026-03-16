/++
  A module containing generic containers used by the library

  Copyright: © 2018-2020 Szabo Bogdan
  License: Subject to the terms of the MIT license, as written in the included LICENSE.txt file.
  Authors: Szabo Bogdan
+/

module vibeauth.identity.collection;

import vibeauth.identity.usermodel;
import vibeauth.identity.token;
import vibeauth.identity.user;
import vibeauth.identity.client;
import vibeauth.identity.clientcollection;
import vibeauth.error;

import std.algorithm;
import std.functional;
import std.range;
import std.exception;
import std.conv;

interface ICollection(T) {
  alias idType = typeof(T.id);

  void add(T item);

  void remove(const idType id);
  void onRemove(void function(T));
  void onRemove(void delegate(T));

  size_t length();
  T opIndex(string index);
  auto opBinaryRight(string op)(idType id);
  int opApply(int delegate(T) dg);
  int opApply(int delegate(ulong, T) dg);
  @property bool empty();
  ICollection!T save();
}


class Collection(T) : ICollection!T {
  alias idType = typeof(T.id);

  protected T[] list;

  private void delegate(T) _onRemove;

  this(T[] list = []) {
    this.list = list;
  }

  void add(T item) {
    enforce(!list.map!(a => a.id).canFind(item.id), "An item with the same id `" ~ item.id.to!string ~ "` already exists");
    list ~= item;
  }

  void remove(const idType id) {
    auto item = list.filter!(a => a.id == id).front;

    raiseOnRemove(item);

    list = list.filter!(a => a.id != id).array;
  }


  void onRemove(void function(T) handler) {
    onRemove(handler.toDelegate);
  }

  void onRemove(void delegate(T) handler) {
    _onRemove = handler;
  }

  size_t length() {
    return list.length;
  }

  T opIndex(string index) {
    static if(is(string == idType)) {
      auto list = list.find!(a => a.id == index);

      enforce!ItemNotFoundException(list.count > 0, "Item not found");

      return list[0];
    } else {
      throw new Exception("not implemented");
    }
  }

  auto opBinaryRight(string op)(idType id) {
    static if (op == "in") {
      return !list.filter!(a => a.id == id).empty;
    } else {
      static assert(false, op ~ " not implemented for `ItemCollection`");
    }
  }

  int opApply(int delegate(T) dg) {
    int result = 0;

    foreach(item; list) {
        result = dg(item);
        if (result)
          break;
    }

    return result;
  }

  int opApply(int delegate(ulong, T) dg) {
    int result = 0;
    ulong idx = 0;

    foreach(item; list) {
      static if(is(size_t == idType)) {
        idx = item.id;
      }

      result = dg(idx, item);

      static if(!is(size_t == idType)) {
        idx++;
      }

      if (result)
        break;
    }

    return result;
  }

  @property bool empty() {
    return list.empty;
  }

  ICollection!T save() {
    return new Collection!T(list.dup);
  }

  private {
    void raiseOnRemove(T item) {
      if(_onRemove is null) {
        return;
      }

      _onRemove(item);
    }
  }
}

version(unittest) {
  import fluent.asserts;

  private Client makeClient(string id, string name) {
    auto c = new Client();
    c.id = id;
    c.name = name;
    return c;
  }
}

@("add stores item and increases length")
unittest {
  auto col = new Collection!Client();
  col.length.should.equal(0);
  col.empty.should.equal(true);

  col.add(makeClient("1", "App1"));

  col.length.should.equal(1);
  col.empty.should.equal(false);
}

@("add throws on duplicate id")
unittest {
  auto col = new Collection!Client();
  col.add(makeClient("1", "App1"));

  ({
    col.add(makeClient("1", "Duplicate"));
  }).should.throwAnyException;
}

@("remove deletes item and triggers onRemove callback")
unittest {
  auto col = new Collection!Client();
  col.add(makeClient("1", "App1"));
  col.add(makeClient("2", "App2"));

  string removedId;
  col.onRemove = (Client c) { removedId = c.id; };

  col.remove("1");

  col.length.should.equal(1);
  removedId.should.equal("1");
}

@("opIndex returns item by id")
unittest {
  auto col = new Collection!Client();
  col.add(makeClient("x", "MyApp"));

  auto item = col["x"];
  item.name.should.equal("MyApp");
}

@("opIndex throws ItemNotFoundException for missing id")
unittest {
  auto col = new Collection!Client();

  ({
    col["missing"];
  }).should.throwException!ItemNotFoundException;
}

@("in operator returns true for existing id")
unittest {
  auto col = new Collection!Client();
  col.add(makeClient("a", "App"));

  ("a" in col).should.equal(true);
}

@("in operator returns false for missing id")
unittest {
  auto col = new Collection!Client();

  ("z" in col).should.equal(false);
}

@("opApply iterates all items")
unittest {
  auto col = new Collection!Client();
  col.add(makeClient("1", "A"));
  col.add(makeClient("2", "B"));
  col.add(makeClient("3", "C"));

  int count = 0;
  foreach (item; col) {
    count++;
  }

  count.should.equal(3);
}

@("save returns independent copy")
unittest {
  auto col = new Collection!Client();
  col.add(makeClient("1", "App"));

  auto copy = col.save();
  col.add(makeClient("2", "Another"));

  col.length.should.equal(2);
  copy.length.should.equal(1);
}
