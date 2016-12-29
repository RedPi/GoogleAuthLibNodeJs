/**
 * Copyright 2015 Google Inc. All Rights Reserved.
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

// Executes the given callback if it is not null.
function callback(c, err, res) {
  if (c) {
    c(err, res);
  }
}

/**
 * User Refresh Token credentials.
 *
 * @param {string} clientId The authentication client ID.
 * @param {string} clientSecret The authentication client secret.
 * @param {string} refreshToken The authentication refresh token.
 * @constructor
 */
class UserRefreshClient extends OAuth2Client {
  constructor (clientId, clientSecret, refreshToken) {
    super(clientId, clientSecret);

    // Named to avoid collision with the method refreshToken_
    this._refreshToken = refreshToken;
  }

  /**
   * Refreshes the access token.
   * @param {object=} ignored_
   * @param {function=} opt_callback Optional callback.
   * @private
   */
  refreshToken_ (ignored_, opt_callback) {
    super.refreshToken_(this._refreshToken, opt_callback);
  }

  /**
   * Create a UserRefreshClient credentials instance using the given input options.
   * @param {object=} json The input object.
   * @param {function=} opt_callback Optional callback.
   */
  fromJSON (json, opt_callback) {
    const that = this;
    if (!json) {
      callback(opt_callback, new Error(
          'Must pass in a JSON object containing the user refresh token'));
      return;
    }
    if (json.type !== 'authorized_user') {
      callback(opt_callback, new Error(
          'The incoming JSON object does not have the "authorized_user" type'));
      return;
    }
    if (!json.client_id) {
      callback(opt_callback, new Error(
          'The incoming JSON object does not contain a client_id field'));
      return;
    }
    if (!json.client_secret) {
      callback(opt_callback, new Error(
          'The incoming JSON object does not contain a client_secret field'));
      return;
    }
    if (!json.refresh_token) {
      callback(opt_callback, new Error(
          'The incoming JSON object does not contain a refresh_token field'));
      return;
    }
    that.clientId_ = json.client_id;
    that.clientSecret_ = json.client_secret;
    that._refreshToken = json.refresh_token;
    that.credentials.refresh_token = json.refresh_token;
    callback(opt_callback);
  }

  /**
   * Create a UserRefreshClient credentials instance using the given input stream.
   * @param {object=} stream The input stream.
   * @param {function=} opt_callback Optional callback.
   */
  fromStream (stream, opt_callback) {
    const that = this;
    if (!stream) {
      process.nextTick(function() {
        callback(
          opt_callback,
          new Error('Must pass in a stream containing the user refresh token.'));
      });
      return;
    }
    let s = '';
    stream.setEncoding('utf8');
    stream.on('data', function (chunk) {
      s += chunk;
    });
    stream.on('end', function () {
      try {
        const data = JSON.parse(s);
        that.fromJSON(data, opt_callback);
      } catch (err) {
        callback(opt_callback, err);
      }
    });
  }
}

/**
 * Export UserRefreshClient
 */
module.exports = UserRefreshClient;
