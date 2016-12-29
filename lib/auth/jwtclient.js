/**
 * Copyright 2013 Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

'use strict';

const OAuth2Client = require('./oauth2client.js');
const gToken = require('gtoken');
const JWTAccess = require('./jwtaccess.js');
const noop = require('lodash.noop');

/**
 * JWT service account credentials.
 *
 * Retrieve access token using gtoken.
 *
 * @param {string=} email service account email address.
 * @param {string=} keyFile path to private key file.
 * @param {string=} key value of key
 * @param {(string|array)=} scopes list of requested scopes or a single scope.
 * @param {string=} subject impersonated account's email address.
 * @constructor
 */
class JWT extends OAuth2Client {
  constructor (email, keyFile, key, scopes, subject) {
    // Don't pass these args to the OAuth2Client constructor
    super();

    this.email = email;
    this.keyFile = keyFile;
    this.key = key;
    this.scopes = scopes;
    this.subject = subject;
    this.gToken = gToken;

    this.credentials = {
      refresh_token: 'jwt-placeholder',
      expiry_date: 1
    };
  }

  /**
   * Creates a copy of the credential with the specified scopes.
   * @param {(string|array)=} scopes List of requested scopes or a single scope.
   * @return {object} The cloned instance.
   */
  createScoped (scopes) {
    return new JWT(this.email, this.keyFile, this.key, scopes, this.subject);
  }

  /**
   * Obtains the metadata to be sent with the request.
   *
   * @param {string} opt_uri the URI being authorized.
   * @param {function} metadataCb
   */
  getRequestMetadata (opt_uri, metadataCb) {
    if (this.createScopedRequired() && opt_uri) {
      // no scopes have been set, but a uri has been provided.  Use JWTAccess credentials.
      const alt = new JWTAccess(this.email, this.key);
      return alt.getRequestMetadata(opt_uri, metadataCb);
    } else {
      return super.getRequestMetadata(opt_uri, metadataCb);
    }
  }

  /**
   * Indicates whether the credential requires scopes to be created by calling createdScoped before
   * use.
   * @return {boolean} false if createScoped does not need to be called.
   */
  createScopedRequired () {
    // If scopes is null, always return true.
    if (this.scopes) {
      // For arrays, check the array length.
      if (this.scopes instanceof Array) {
        return this.scopes.length === 0;
      }

      // For others, convert to a string and check the length.
      return String(this.scopes).length === 0;
    }

    return true;
  }

  /**
   * Get the initial access token using gToken.
   * @param {function=} opt_callback Optional callback.
   */
  authorize (opt_callback) {
    const done = opt_callback || noop;

    this.refreshToken_(null, (err, result) => {
      if (!err) {
        this.credentials = result;
        this.credentials.refresh_token = 'jwt-placeholder';
        this.key = this.gtoken.key;
        this.email = this.gtoken.iss;
      }
      done(err, result);
    });
  }

  /**
   * Refreshes the access token.
   * @param {object=} ignored_
   * @param {function=} opt_callback Optional callback.
   * @private
   */
  refreshToken_ (ignored_, opt_callback) {
    const done = opt_callback || noop;

    return this._createGToken((err, gToken) => {
      if (err) {
        return done(err);
      } else {
        return gToken.getToken((err, token) => {
          return done(err, {
            access_token: token,
            token_type: 'Bearer',
            expiry_date: gToken.expires_at
          });
        });
      }
    });
  }

  /**
   * Create a JWT credentials instance using the given input options.
   * @param {object=} json The input object.
   * @param {function=} opt_callback Optional callback.
   */
  fromJSON (json, opt_callback) {
    const done = opt_callback || noop;
    if (!json) {
      done(new Error(
        'Must pass in a JSON object containing the service account auth settings.'));
      return;
    }
    if (!json.client_email) {
      done(new Error(
        'The incoming JSON object does not contain a client_email field'));
      return;
    }
    if (!json.private_key) {
      done(new Error(
        'The incoming JSON object does not contain a private_key field'));
      return;
    }
    // Extract the relevant information from the json key file.
    this.email = json.client_email;
    this.key = json.private_key;
    this.projectId = json.project_id;
    done();
  }

  /**
   * Create a JWT credentials instance using the given input stream.
   * @param {object=} stream The input stream.
   * @param {function=} opt_callback Optional callback.
   */
  fromStream (stream, opt_callback) {
    const done = opt_callback || noop;

    if (!stream) {
      process.nextTick(() => {
        done(
          new Error('Must pass in a stream containing the service account auth settings.'));
      });
      return;
    }
    let s = '';
    stream.setEncoding('utf8');
    stream.on('data', (chunk) => {
      s += chunk;
    });
    stream.on('end', () => {
      try {
        const data = JSON.parse(s);
        this.fromJSON(data, opt_callback);
      } catch (err) {
        done(err);
      }
    });
  }

  /**
   * Creates the gToken instance if it has not been created already.
   * @param {function=} callback Callback.
   * @private
   */
  _createGToken (callback) {
    if (this.gtoken) {
      return callback(null, this.gtoken);
    } else {
      this.gtoken = this.gToken({
        iss: this.email,
        sub: this.subject,
        scope: this.scopes,
        keyFile: this.keyFile,
        key: this.key
      });
      return callback(null, this.gtoken);
    }
  }
}

/**
 * Export JWT.
 */
module.exports = JWT;
