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

const assert = require('assert');
const GoogleAuth = require('../lib/auth/googleauth.js');
const nock = require('nock');
const fs = require('fs');

nock.disableNetConnect();

// Creates a standard JSON credentials object for testing.
function createJSON() {
  return {
    'client_secret': 'privatekey',
    'client_id': 'client123',
    'refresh_token': 'refreshtoken',
    'type': 'authorized_user'
  };
}

describe('Refresh Token auth client', function() {

});

describe('.fromJson', function () {

  it('should error on null json', function (done) {
    const auth = new GoogleAuth();
    const refresh = new auth.UserRefreshClient();
    refresh.fromJSON(null, function (err) {
      assert.equal(true, err instanceof Error);
      done();
    });
  });

  it('should error on empty json', function (done) {
    const auth = new GoogleAuth();
    const refresh = new auth.UserRefreshClient();
    refresh.fromJSON({}, function (err) {
      assert.equal(true, err instanceof Error);
      done();
    });
  });

  it('should error on missing client_id', function (done) {
    const json = createJSON();
    delete json.client_id;

    const auth = new GoogleAuth();
    const refresh = new auth.UserRefreshClient();
    refresh.fromJSON(json, function (err) {
      assert.equal(true, err instanceof Error);
      done();
    });
  });

  it('should error on missing client_secret', function (done) {
    const json = createJSON();
    delete json.client_secret;

    const auth = new GoogleAuth();
    const refresh = new auth.UserRefreshClient();
    refresh.fromJSON(json, function (err) {
      assert.equal(true, err instanceof Error);
      done();
    });
  });

  it('should error on missing refresh_token', function (done) {
    const json = createJSON();
    delete json.refresh_token;

    const auth = new GoogleAuth();
    const refresh = new auth.UserRefreshClient();
    refresh.fromJSON(json, function (err) {
      assert.equal(true, err instanceof Error);
      done();
    });
  });

  it('should create UserRefreshClient with clientId_', function(done) {
    const json = createJSON();
    const auth = new GoogleAuth();
    const refresh = new auth.UserRefreshClient();
    refresh.fromJSON(json, function (err) {
      assert.ifError(err);
      assert.equal(json.client_id, refresh.clientId_);
      done();
    });
  });

  it('should create UserRefreshClient with clientSecret_', function(done) {
    const json = createJSON();
    const auth = new GoogleAuth();
    const refresh = new auth.UserRefreshClient();
    refresh.fromJSON(json, function (err) {
      assert.ifError(err);
      assert.equal(json.client_secret, refresh.clientSecret_);
      done();
    });
  });

  it('should create UserRefreshClient with _refreshToken', function(done) {
    const json = createJSON();
    const auth = new GoogleAuth();
    const refresh = new auth.UserRefreshClient();
    refresh.fromJSON(json, function (err) {
      assert.ifError(err);
      assert.equal(json.refresh_token, refresh._refreshToken);
      done();
    });
  });
});

describe('.fromStream', function () {

  it('should error on null stream', function (done) {
    const auth = new GoogleAuth();
    const refresh = new auth.UserRefreshClient();
    refresh.fromStream(null, function (err) {
      assert.equal(true, err instanceof Error);
      done();
    });
  });

  it('should read the stream and create a UserRefreshClient', function (done) {
    // Read the contents of the file into a json object.
    const fileContents = fs.readFileSync('./test/fixtures/refresh.json', 'utf-8');
    const json = JSON.parse(fileContents);

    // Now open a stream on the same file.
    const stream = fs.createReadStream('./test/fixtures/refresh.json');

    // And pass it into the fromStream method.
    const auth = new GoogleAuth();
    const refresh = new auth.UserRefreshClient();
    refresh.fromStream(stream, function (err) {
      assert.ifError(err);

      // Ensure that the correct bits were pulled from the stream.
      assert.equal(json.client_id, refresh.clientId_);
      assert.equal(json.client_secret, refresh.clientSecret_);
      assert.equal(json.refresh_token, refresh._refreshToken);

      done();
    });
  });
});
