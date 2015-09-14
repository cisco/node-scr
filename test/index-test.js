/**!
 *
 * Copyright (c) 2015 Cisco Systems, Inc. See LICENSE file.
 */
 "use strict";

var chai = require("chai");
var SCR = require("../"),
    jose = require("node-jose");

var assert = chai.assert;

describe("scr", function() {
  describe("basics", function() {
    var inst;
    beforeEach(function() {
      var promise = SCR.create();
      promise = promise.then(function(scr) {
        inst = scr;
      });
      return promise;
    });
    afterEach(function() {
      inst = undefined;
    });

    it("creates an SCR", function() {
      assert.equal(inst.enc, "A256GCM");
      assert.isNotNull(inst.key);
      assert.isNotNull(inst.iv);
      assert.notEqual(inst.aad, "");
      assert.isUndefined(inst.loc);
      assert.isUndefined(inst.tag);

      inst.loc = "https://example.com/some/empty/content";
      assert.equal(inst.loc, "https://example.com/some/empty/content");
    });

    it("exports JSON", function() {
      var expected = {
        enc: "A256GCM",
        key: jose.util.base64url.encode(inst.key.get("k", true)),
        iv: jose.util.base64url.encode(inst.iv),
        aad: inst.aad
      };
      var actual = inst.toJSON();

      assert.deepEqual(actual, expected);
    });
  });
  describe("crypto", function() {
    var jwk,
        content,
        ciphertext,
        inSCR,
        outSCR;
    beforeEach(function() {
      var promise = Promise.all([
        (function(amt) {
          var content = new Buffer(amt);
          for (var idx = 0; content.length > idx; idx++) {
            content[idx] = (idx % 256);
          }

          return content;
        })(1024 + 1),
        SCR.create(),
        jose.JWK.asKey({
            "kty": "oct",
            "kid": "https://encryption-a.wbx2.com/encryption/api/v1/keys/c1724e0b-4c97-4729-8557-16237df054b6",
            "k": "ZKgRS3h2nrkblZtre72wusJcg3RJanqj0022-kw_NiE"
        })
      ]).then(function(results) {
        content = results[0];
        outSCR = results[1];
        jwk = results[2];
        ciphertext = undefined;
        inSCR = undefined;
      });
      return promise;
    });

    it("roundtrips an empty SCR as a JWE", function() {
      var promise = Promise.resolve(outSCR);
      promise = promise.then(function(scr) {
        return scr.toJWE(jwk);
      });
      promise = promise.then(function(jwe) {
        assert.ok("string" === typeof jwe);

        return SCR.fromJWE(jwk, jwe);
      });
      promise = promise.then(function(scr) {
        inSCR = scr;

        var actual = inSCR.toJSON(),
            expected = outSCR.toJSON();
        assert.deepEqual(actual, expected);
      });
      return promise;
    });
    it("roundtrips and empty SCR as a JWE (key as JSON)", function() {
      var jwk = {
        "kty": "oct",
        "kid": "https://encryption-a.wbx2.com/encryption/api/v1/keys/c1724e0b-4c97-4729-8557-16237df054b6",
        "k": "ZKgRS3h2nrkblZtre72wusJcg3RJanqj0022-kw_NiE"
      };
      var promise = Promise.resolve(outSCR);
      promise = promise = promise.then(function(scr) {
        return scr.toJWE(jwk);
      });
      promise = promise.then(function(jwe) {
        assert.ok("string" === typeof jwe);
        return SCR.fromJWE(jwk, jwe);
      });
      promise = promise.then(function(scr) {
        inSCR = scr;

        var actual = inSCR.toJSON(),
            expected = outSCR.toJSON();
        assert.deepEqual(actual, expected);
      });
      return promise;
    });
    it("roundtrips and empty SCR as a JWE (key as string)", function() {
      var jwk = {
        "kty": "oct",
        "kid": "https://encryption-a.wbx2.com/encryption/api/v1/keys/c1724e0b-4c97-4729-8557-16237df054b6",
        "k": "ZKgRS3h2nrkblZtre72wusJcg3RJanqj0022-kw_NiE"
      };
      var promise = Promise.resolve(outSCR);
      promise = promise = promise.then(function(scr) {
        return scr.toJWE(JSON.stringify(jwk));
      });
      promise = promise.then(function(jwe) {
        assert.ok("string" === typeof jwe);
        return SCR.fromJWE(jwk, jwe);
      });
      promise = promise.then(function(scr) {
        inSCR = scr;

        var actual = inSCR.toJSON(),
            expected = outSCR.toJSON();
        assert.deepEqual(actual, expected);
      });
      return promise;
    });

    it("roundtrips protected content (input as Buffer)", function() {
      var promise = Promise.resolve();
      promise = promise.then(function() {
        return outSCR.encrypt(content);
      });
      promise = promise.then(function(ciphered) {
        assert.ok(outSCR.tag);
        assert.equal(ciphered.length, content.length);

        return outSCR.decrypt(ciphered);
      });
      promise = promise.then(function(deciphered) {
        assert.deepEqual(deciphered, content);
      });
      return promise;
    });
    it("roundtrips protected content (input as string)", function() {
      var promise = Promise.resolve();
      promise = promise.then(function() {
        return outSCR.encrypt(content.toString("binary"));
      });
      promise = promise.then(function(ciphered) {
        assert.ok(outSCR.tag);
        assert.equal(ciphered.length, content.length);

        return outSCR.decrypt(ciphered);
      });
      promise = promise.then(function(deciphered) {
        assert.deepEqual(deciphered, content);
      });
      return promise;
    });
    it("roundtrips protected content (input as TypedArray)", function() {
      var promise = Promise.resolve();
      promise = promise.then(function() {
        var input = new Uint8Array(content);
        return outSCR.encrypt(input);
      });
      promise = promise.then(function(ciphered) {
        assert.ok(outSCR.tag);
        assert.equal(ciphered.length, content.length);

        return outSCR.decrypt(ciphered);
      });
      promise = promise.then(function(deciphered) {
        assert.deepEqual(deciphered, content);
      });
      return promise;
    });
    it("roundtrips protected content (input as ArrayBuffer)", function() {
      var promise = Promise.resolve();
      promise = promise.then(function() {
        var input = new Uint8Array(content);
        return outSCR.encrypt(input.buffer);
      });
      promise = promise.then(function(ciphered) {
        assert.ok(outSCR.tag);
        assert.equal(ciphered.length, content.length);

        return outSCR.decrypt(ciphered);
      });
      promise = promise.then(function(deciphered) {
        assert.deepEqual(deciphered, content);
      });
      return promise;
    });

    it("roundtrips everything", function() {
      var promise = Promise.resolve();
      promise = promise.then(function() {
        return outSCR.encrypt(content);
      });
      promise = promise.then(function(ciphered) {
        assert.ok(outSCR.tag);
        assert.ok(ciphered.length, content.length);
        ciphertext = ciphered;

        outSCR.loc = "https://example.com/some/dummy/content";
        return outSCR.toJWE(jwk);
      });
      promise = promise.then(function(jwe) {
        assert.equal(typeof jwe, "string");
        assert.ok(jwe.length);

        return SCR.fromJWE(jwk, jwe);
      });
      promise = promise.then(function(scr) {
        inSCR = scr;

        var actual = inSCR.toJSON(),
            expected = outSCR.toJSON();
        assert.deepEqual(actual, expected);

        return inSCR.decrypt(ciphertext);
      });
      promise = promise.then(function(plaintext) {
        assert.deepEqual(plaintext, content);
      });

      return promise;
    });
  });
});
