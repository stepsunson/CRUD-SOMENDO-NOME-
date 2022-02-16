--[[ json.lua

A compact pure-Lua JSON library.

This code is in the public domain:
https://gist.github.com/tylerneylon/59f4bcf316be525b30ab

The main functions are: json.stringify, json.parse.

## json.stringify:

This expects the following to be true of any tables being encoded:
 * They only have string or number keys. Number keys must be represented as
   strings in json; this is part of the json spec.
 * They are not recursive. Such a structure cannot be specified in json.

A Lua table is considered to be an array if and only if its set of keys is a
consecutive sequence of positive integers starting at 1. Arrays are encoded like
so: `[2, 3, false, "hi"]`. Any other type of Lua table is encoded as a json
object, encoded like so: `{"key1": 2, "key2": false}`.

Because the Lua nil value cannot be a key, and as a table value is considered
equivalent to a missing key, there is no way to express the json "null" value in
a Lua table. The only way this will output "null" is if your entire input obj is
nil itself.

An empty Lua table, {}, could be considered either