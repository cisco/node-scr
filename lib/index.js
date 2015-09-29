/*!
 * lib/index.js -- SCR Implementation
 *
 * Copyright (c) 2015 Cisco Systems, Inc. See LICENSE file.
 */
 "use strict";

var clone = require("lodash.clone"),
    jose = require("node-jose");

/**
 * @class SCRObject
 * @classdesc
 * Representation of a Secure Content Resource (SCR).
 *
 * Instances of this class are not created directly, but instead through
 * {@link SCR.create}, {@link SCR.fromJSON}, or {@link SCR.fromJWE}.
 */

/**
 * @desc
 * Creates a new SCR, optionally with the given configuration.
 *
 * `cfg`, if provided, is expected to match the output from
 * {@link SCRObject#toJSON}.
 *
 * @param {Object} [cfg] The configuration object
 * @private
 */
function SCRObject(cfg) {
  cfg.loc = cfg.loc || undefined;
  cfg.tag = cfg.tag || undefined;

  /**
   * The algorithm used to encrypt the content.
   *
   * @member {String} enc
   * @memberof SCRObject#
   */
  Object.defineProperty(this, "enc", {
    get: function() {
      return cfg.enc;
    },
    enumerable: true
  });
  /**
   * The key used to encrypt the content.
   *
   * @member {jose.JWK.Key} key
   * @memberof SCRObject#
   */
  Object.defineProperty(this, "key", {
    get: function() {
      return cfg.key;
    },
    enumerable: true
  });
  /**
   * The initialization vector used to encrypt the content.
   *
   * @member {Buffer} iv
   * @memberof SCRObject#
   */
  Object.defineProperty(this, "iv", {
    get: function() {
      return cfg.iv;
    },
    enumerable: true
  });
  /**
   * The additional authenticated data used to encrypt the content.
   *
   * @member {String} aad
   * @memberof SCRObject#
   */
  Object.defineProperty(this, "aad", {
    get: function() {
      return cfg.aad;
    },
    enumerable: true
  });
  /**
   * The location where encrypted content can be found.
   *
   * @member {String} loc
   * @memberof SCRObject#
   */
  Object.defineProperty(this, "loc", {
    get: function() {
      return cfg.loc;
    },
    set: function(loc) {
      cfg.loc = loc;
    },
    enumerable: true
  });
  /**
   * The authentication tag from encrypting content.
   *
   * @member {Buffer} tag
   * @memberof SCRObject#
   */
  Object.defineProperty(this, "tag", {
    get: function() {
      return cfg.tag;
    },
    enumerable: true
  });

  /**
   * Generates a JSON representation of this SCR.
   *
   * @function toJSON
   * @memberof SCRObject#
   * @returns {Object} The JSON representation of this SCR
   */
  Object.defineProperty(this, "toJSON", {
    value: function() {
      var key = cfg.key.get("k", true);
      var data = {};
      data.enc = cfg.enc;
      data.key = jose.util.base64url.encode(key);
      data.iv = jose.util.base64url.encode(cfg.iv);
      data.aad = cfg.aad;

      if (cfg.loc) {
        data.loc = cfg.loc;
      }
      if (cfg.tag) {
        data.tag = jose.util.base64url.encode(cfg.tag);
      }

      return data;
    }
  });
  /**
   * Encrypts the JSON representation of this SCR.
   *
   * @function toJWE
   * @memberof SCRObject#
   * @param {jose.JWK} jwk The key to encrypt this SCR with
   * @returns {Promise} A Promise for the encrypted SCR (when fulfilled)
   */
  Object.defineProperty(this, "toJWE", {
    value: function(jwk) {
      var self = this,
          promise;
      promise = jose.JWK.asKey(jwk);
      promise = promise.then(function(jwk) {
        var rcpt = {
          header: {
            alg: "dir"
          },
          key: jwk,
          reference: false
        };
        var opts = {
          compact: true,
          contentAlg: cfg.enc
        };

        var data = self.toJSON();
        data = JSON.stringify(data);
        return jose.JWE.createEncrypt(opts, rcpt).
               final(data, "utf8");
      });

      return promise;
    }
  });

  /**
   * Encrypts the given content. Content is encrypted using the
   * {@link SCRObject#key}, {@link SCRObject#iv}, and {@link SCRObject#aad}.
   *
   * When the returned Promise is fulfilled, any resolved callbacks are passed
   * the encrypted content as a Buffer, and {@link SCRObject#tag} is modified to
   * contain the encrypted content's authentication tag.
   *
   * @function encrypt
   * @memberof SCRObject#
   * @param {Buffer|ArrayBuffer|ArrayBufferView} pdata The content to encrypt.
   * @returns {Promise} A Promise for the encrypted content (when fulfilled)
   */
  Object.defineProperty(this, "encrypt", {
    value: function(pdata) {
      var props = {
        iv: cfg.iv,
        adata: new Buffer(cfg.aad, "utf8")
      };

      // condition the data before encrypting
      pdata = jose.util.asBuffer(pdata);
      return cfg.key.encrypt(cfg.enc, pdata, props).
             then(function(result) {
                var cdata = result.data;
                cfg.tag = result.tag;

                return cdata;
             });
    }
  });
  /**
   * Decrypts the given content. Content is decrypted using the {@link SCRObject#key},
   * {@link SCRObject#iv}, {@link SCRObject#aad}, and {@link SCRObject#tag}.
   *
   * When the returned Promise is fulfilled, any resolved callbacks are passed
   * the decrypted content as a Buffer.
   *
   * @function decrypt
   * @memberof SCRObject#
   * @param {Buffer|ArrayBuffer|ArrayBufferView} pdata The content to encrypt.
   * @returns {Promise} A Promise for the encrypted content (when fulfilled)
   */
  Object.defineProperty(this, "decrypt", {
    value: function(cdata) {
        var props = {
          iv: cfg.iv,
          adata: new Buffer(cfg.aad, "utf8"),
          mac: cfg.tag
        };

        // condition data before decrypting
        cdata = jose.util.asBuffer(cdata);
        return cfg.key.decrypt(cfg.enc, cdata, props).
               then(function(pdata) {
                  return pdata;
               });
    }
  });
}

/**
 * Entry point namespace Secure Content Resources.
 *
 * @namespace SCR
 */
var SCR = {
  /**
   * Creates a new {@link SCRObject} initialized with a content encryption key.
   *
   * The returned promise, when fulfilled, returns the new SCR instance to
   * all resolve callbacks.
   *
   * @returns {Promise} A promise for a new SCR.
   */
  create: function() {
    // TODO: make this more configurable
    var iv = jose.util.randomBytes(12);
    var aad = new Date().toISOString();

    var keystore = jose.JWK.createKeyStore();
    var promise = keystore.generate("oct", 256);
    promise = promise.then(function(key) {
      return new SCRObject({
        enc: "A256GCM",
        key: key,
        iv: iv,
        aad: aad
      });
    });

    return promise;
  },
  /**
   * Decrypts an encrypted SCR into a {@link SCRObject} instance.
   *
   * The returned promise, when fulfilled, returns the decrypted SCR to all
   * resolve callbacks.
   *
   * @param {jose.JWK.Key} jwk The key to decrypt the SCR with
   * @param {String | Object} jwe The encrypted SCR to decrypt
   * @returns {Promise} A promise for the decrypted SCR
   */
  fromJWE: function(jwk, jwe) {
    var promise;
    promise = jose.JWK.asKey(jwk);
    promise = promise.then(function(jwk) {
      return jose.JWE.createDecrypt(jwk).decrypt(jwe);
    });
    promise = promise.then(function(result) {
      result = result.plaintext.toString("utf8");
      result = JSON.parse(result);
      return SCR.fromJSON(result);
    });

    return promise;
  },
  /**
   * Parses the given JSON representation into a {@link SCRObject} instance.
   *
   * The returned promise, when fulfilled, returns the parsed SCR
   * to all resolve callbacks.
   *
   * @param {Object} json The JSON representation of a SCR
   * @returns {Promise} A promise for the parsed SCR instance
   */
  fromJSON: function(json) {
    // create a copy to mitigate tampering
    var cfg = clone(json);

    var promise;
    if (json.key) {
      promise = jose.JWK.asKey({
        kty: "oct",
        k: json.key
      });
    } else {
      promise = Promise.resolve();
    }
    promise = promise.then(function(key) {
      if (key) {
        cfg.key = key;
      }

      if ("iv" in cfg) {
        cfg.iv = Buffer.isBuffer(cfg.iv) ?
                 cfg.iv :
                 jose.util.base64url.decode(cfg.iv);
      }
      if ("tag" in cfg) {
        cfg.tag = Buffer.isBuffer(cfg.tag) ?
                  cfg.tag :
                  jose.util.base64url.decode(cfg.tag);
      }

      return new SCRObject(cfg);
    });

    return promise;
  }
};

module.exports = SCR;
