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
import std.array;

import std.range.interfaces;
import std.range.primitives;

class ItemNotFoundException : Exception {
  this(string msg = null, Throwable next = null) { super(msg, next); }
  this(string msg, string file, size_t line, Throwable next = null) {
    super(msg, file, line, next);
  }
}

class Collection(T) {
  alias idType = typeof(T.id);

	protected T[] list;

	this(T[] list = []) {
    this.list = list;
	}

	void add(T item) {
    enforce(!list.map!(a => a.id).canFind(item.id), "An item with the same id `" ~ item.id.to!string ~ "` already exists");
		list ~= item;
	}

  void remove(const idType id) {
    list = list.filter!(a => a.id != id).array;
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

  Collection!T save() {
    return new Collection!T(list.dup);
  }
}
