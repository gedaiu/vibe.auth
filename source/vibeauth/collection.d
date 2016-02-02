module vibeauth.collection;

import vibe.data.json;

import std.traits;
import std.stdio;
import std.algorithm.searching;
import std.algorithm.iteration;
import std.exception;
import std.uuid;
import std.conv;
import std.datetime;

class ItemNotFoundException : Exception {
  this(string msg = null, Throwable next = null) { super(msg, next); }
  this(string msg, string file, size_t line, Throwable next = null) {
    super(msg, file, line, next);
  }
}

class Collection(T) {
  long index = 0;
  alias idType = typeof(T.id);

	protected T[] list;

	this(T[] list = []) {
    this.list = list;
	}

	void add(T item) {
    enforce(!list.map!(a => a.id).canFind(item.id), "An item with the same id already exists");
		list ~= item;
	}

  auto length() {
    return list.length;
  }

  auto opIndex(idType index) {
    auto list = list.find!(a => a.id == index);

		enforce!ItemNotFoundException(list.count > 0, "Item not found");

		return list[0];
	}

  auto opBinaryRight(string op)(idType id) {
		static if (op == "in") {
			return !list.filter!(a => a.id == id).empty;
		} else {
			static assert(false, op ~ " not implemented for `ItemCollection`");
		}
	}

  int opApply(int delegate(ref T) dg) {
    int result = 0;

    foreach(item; list) {
        result = dg(item);
        if (result)
          break;
    }

    return result;
  }

  @property auto front() {
    return list[index];
  }

  auto moveFront() {
    index = 0;
    return front();
  }

  void popFront() {
    index++;
  }

  @property bool empty() {
    return index >= list.length;
  }
}
