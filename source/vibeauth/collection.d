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
import std.functional;

import std.range.interfaces;
import std.range.primitives;

private import vibeauth.error;

deprecated("use vibeauth.error.ItemNotFoundException instead") alias ItemNotFoundException = vibeauth.error.ItemNotFoundException;

deprecated("use vibeauth.collections.base.ICollection instead") alias ICollection = vibeauth.collections.base.ICollection;

deprecated("use vibeauth.collections.base.BaseCollection instead") alias Collection = vibeauth.collections.base.Collection;
