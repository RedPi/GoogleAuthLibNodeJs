/**
 * Copyright 2014 Google Inc. All Rights Reserved.
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

const JWTClient = require('./jwtclient.js');
const ComputeClient = require('./computeclient.js');
const exec = require('child_process').exec;
const fs = require('fs');
const os = require('os');
const path = require('path');
const util = require('util');
const DefaultTransporter = require('../transporters.js');

// Executes the given callback if it is not null.
function callback(c) {
  if (c) {
    return c.apply(null, Array.prototype.slice.call(arguments, 1));
  }
}

// Creates an Error containing the given message, and includes the message from the optional err
// passed in.
function createError(message, err) {
  let s = message || '';
  if (err) {
    const errorMessage = String(err);
    if (errorMessage && errorMessage.length > 0) {
      if (s.length > 0) {
        s += ' ';
      }
      s += errorMessage;
    }
  }
  return Error(s);
}

/**
 * GoogleAuth account manager.
 *
 * @constructor
 */
class GoogleAuth {
  constructor () {
    this.JWTClient = JWTClient;
    this.ComputeClient = ComputeClient;
    this._cachedCredential = null;
  }

  /**
   * Convenience field mapping in the IAM credential type.
   */
  get IAMAuth () {
    return require('./iam.js');
  }

  /**
   * Convenience field mapping in the Compute credential type.
   */
  get Compute () {
    return require('./computeclient.js');
  }

  /**
   * Convenience field mapping in the JWT credential type.
   */
  get JWT () {
    return require('./jwtclient.js');
  }

  /**
   * Convenience field mapping in the JWT Access credential type.
   */
  get JWTAccess () {
    return require('./jwtaccess.js');
  }

  /**
   * Convenience field mapping in the OAuth2 credential type.
   */
  get OAuth2 () {
    return require('./oauth2client.js');
  }

  /**
   * Convenience field mapping to the UserRefreshClient credential type.
   */
  get UserRefreshClient () {
    return require('./refreshclient.js');
  }

  /**
   * Obtains the default project ID for the application..
   * @param {function=} opt_callback Optional callback.
   */
  getDefaultProjectId (opt_callback) {
    // In implicit case, supports three environments. In order of precedence, the
    // implicit environments are:
    //
    // * GCLOUD_PROJECT or GOOGLE_CLOUD_PROJECT environment variable
    // * GOOGLE_APPLICATION_CREDENTIALS JSON file
    // * Get default service project from
    //  ``$ gcloud beta auth application-default login``
    // * Google App Engine application ID (Not implemented yet)
    // * Google Compute Engine project ID (from metadata server) (Not implemented yet)

    if (this._cachedProjectId) {
      process.nextTick(() => {
        callback(opt_callback, null, this._cachedProjectId);
      });
    } else {
      const my_callback = (err, projectId) => {
        if (!err && projectId) {
          this._cachedprojectId = projectId;
        }
        process.nextTick(() => {
          callback(opt_callback, err, projectId);
        });
      };

      // environment variable
      if (this._getProductionProjectId(my_callback)) {
        return;
      }

      // json file
      this._getFileProjectId((err, projectId) => {
        if (err || projectId) {
          my_callback(err, projectId);
          return;
        }

        // Google Cloud SDK default project id
        this._getDefaultServiceProjectId((err, projectId) => {
          if (err || projectId) {
            my_callback(err, projectId);
            return;
          }

          // Get project ID from Compute Engine metadata server
          this._getGCEProjectId(my_callback);
        });
      });
    }
  }

  /**
   * Loads the project id from environment variables.
   * @param {function} _callback Callback.
   * @api private
   */
  _getProductionProjectId (_callback) {
    const projectId = this._getEnv('GCLOUD_PROJECT') || this._getEnv('GOOGLE_CLOUD_PROJECT');
    if (projectId) {
      process.nextTick(() => {
        callback(_callback, null, projectId);
      });
    }
    return projectId;
  }

  /**
   * Loads the project id from the GOOGLE_APPLICATION_CREDENTIALS json file.
   * @param {function} _callback Callback.
   * @api private
   */
  _getFileProjectId (_callback) {
    if (this._cachedCredential) {
      // Try to read the project ID from the cached credentials file
      process.nextTick(() => {
        callback(_callback, null, this._cachedCredential.projectId);
      });
      return;
    }

    // Try to load a credentials file and read its project ID
    const pathExists = this._tryGetApplicationCredentialsFromEnvironmentVariable((err, result) => {
        if (!err && result) {
          callback(_callback, null, result.projectId);
          return;
        }
        callback(_callback, err);
      }
    );

    if (!pathExists) {
      callback(_callback, null);
    }
  }

  /**
   * Loads the default project of the Google Cloud SDK.
   * @param {function} _callback Callback.
   * @api private
   */
  _getDefaultServiceProjectId (_callback) {
    this._getSDKDefaultProjectId((err, stdout) => {
      let projectId;
      if (!err && stdout) {
        try {
          projectId = JSON.parse(stdout).core.project;
        } catch (err) {
          projectId = null;
        }
      }
      // Ignore any errors
      callback(_callback, null, projectId);
    });
  }

  /**
   * Run the Google Cloud SDK command that prints the default project ID
   * @param {function} _callback Callback.
   * @api private
   */
  _getSDKDefaultProjectId (_callback) {
    exec('gcloud -q config list core/project --format=json', _callback);
  }

  /**
   * Gets the Compute Engine project ID if it can be inferred.
   * Uses 169.254.169.254 for the metadata server to avoid request
   * latency from DNS lookup.
   * See https://cloud.google.com/compute/docs/metadata#metadataserver
   * for information about this IP address. (This IP is also used for
   * Amazon EC2 instances, so the metadata flavor is crucial.)
   * See https://github.com/google/oauth2client/issues/93 for context about
   * DNS latency.
   *
   * @param {function} _callback Callback.
   * @api private
   */
  _getGCEProjectId (_callback) {
    if (!this.transporter) {
      this.transporter = new DefaultTransporter();
    }
    this.transporter.request({
      method: 'GET',
      uri: 'http://169.254.169.254/computeMetadata/v1/project/project-id',
      headers: {
        'Metadata-Flavor': 'Google'
      }
    }, (err, body, res) => {
      if (err || !res || res.statusCode !== 200 || !body) {
        callback(_callback, null);
        return;
      }
      // Ignore any errors
      callback(_callback, null, body);
    });
  }

  /**
   * Obtains the default service-level credentials for the application..
   * @param {function=} opt_callback Optional callback.
   */
  getApplicationDefault (opt_callback) {
    // If we've already got a cached credential, just return it.
    if (this._cachedCredential) {
      process.nextTick(() => {
        callback(opt_callback, null, this._cachedCredential, this._cachedProjectId);
      });
    } else {
      // Inject our own callback routine, which will cache the credential once it's been created.
      // It also allows us to ensure that the ultimate callback is always async.
      const my_callback = (err, result) => {
        if (!err && result) {
          this._cachedCredential = result;
          this.getDefaultProjectId((err, projectId) => {
            process.nextTick(() => {
              // Ignore default project error
              callback(opt_callback, null, result, projectId);
            });
          });
        } else {
          process.nextTick(() => {
            callback(opt_callback, err, result);
          });
        }
      };
      // Check for the existence of a local environment variable pointing to the
      // location of the credential file. This is typically used in local developer scenarios.
      if (this._tryGetApplicationCredentialsFromEnvironmentVariable(my_callback)) {
        return;
      }

      // Look in the well-known credential file location.
      if (this._tryGetApplicationCredentialsFromWellKnownFile(my_callback)) {
        return;
      }

      // Determine if we're running on GCE.
      this._checkIsGCE((gce) => {
        if (gce) {
          // For GCE, just return a default ComputeClient. It will take care of the rest.
          my_callback(null, new this.ComputeClient());
        } else {
          // We failed to find the default credentials. Bail out with an error.
          my_callback(new Error('Could not load the default credentials. Browse to ' +
            'https://developers.google.com/accounts/docs/application-default-credentials for ' +
            'more information.'));
        }
      });
    }
  }

  /**
   * Determines whether the auth layer is running on Google Compute Engine.
   * @param {function=} callback The callback.
   * @api private
   */
  _checkIsGCE (callback) {
    if (this._checked_isGCE) {
      callback(this._isGCE);
    } else {
      if (!this.transporter) {
        this.transporter = new DefaultTransporter();
      }
      this.transporter.request({
        method: 'GET',
        uri: 'http://metadata.google.internal',
        json: true
      }, (err, body, res) => {
        if (!err && res && res.headers) {
          this._isGCE = res.headers['metadata-flavor'] === 'Google';
        }
        this._checked_isGCE = true;
        callback(this._isGCE);
      });
    }
  }

  /**
   * Attempts to load default credentials from the environment variable path..
   * @param {function=} opt_callback Optional callback.
   * @return {boolean} Returns true if the callback has been executed; false otherwise.
   * @api private
   */
  _tryGetApplicationCredentialsFromEnvironmentVariable (opt_callback) {
    const credentialsPath = this._getEnv('GOOGLE_APPLICATION_CREDENTIALS');
    if (!credentialsPath || credentialsPath.length === 0) {
      return false;
    }
    this._getApplicationCredentialsFromFilePath(credentialsPath, (err, result) => {
      let wrappedError = null;
      if (err) {
        wrappedError = createError(
            'Unable to read the credential file specified by the GOOGLE_APPLICATION_CREDENTIALS ' +
            'environment variable.',
          err);
      }
      callback(opt_callback, wrappedError, result);
    });
    return true;
  }

  /**
   * Attempts to load default credentials from a well-known file location
   * @param {function=} opt_callback Optional callback.
   * @return {boolean} Returns true if the callback has been executed; false otherwise.
   * @api private
   */
  _tryGetApplicationCredentialsFromWellKnownFile (opt_callback) {
    // First, figure out the location of the file, depending upon the OS type.
    let location = null;
    if (this._isWindows()) {
      // Windows
      location = this._getEnv('APPDATA');
    } else {
      // Linux or Mac
      const home = this._getEnv('HOME');
      if (home) {
        location = this._pathJoin(home, '.config');
      }
    }
    // If we found the root path, expand it.
    if (location) {
      location = this._pathJoin(location, 'gcloud');
      location = this._pathJoin(location, 'application_default_credentials.json');
      location = this._mockWellKnownFilePath(location);
      // Check whether the file exists.
      if (!this._fileExists(location)) {
        location = null;
      }
    }
    // The file does not exist.
    if (!location) {
      return false;
    }
    // The file seems to exist. Try to use it.
    this._getApplicationCredentialsFromFilePath(location, opt_callback);
    return true;
  }

  /**
   * Attempts to load default credentials from a file at the given path..
   * @param {string=} filePath The path to the file to read.
   * @param {function=} opt_callback Optional callback.
   * @api private
   */
  _getApplicationCredentialsFromFilePath (filePath, opt_callback) {
    let error = null;
    // Make sure the path looks like a string.
    if (!filePath || filePath.length === 0) {
      error = new Error('The file path is invalid.');
    }

    // Make sure there is a file at the path. lstatSync will throw if there is nothing there.
    if (!error) {
      try {
        // Resolve path to actual file in case of symlink. Expect a thrown error if not resolvable.
        filePath = fs.realpathSync(filePath);

        if (!fs.lstatSync(filePath).isFile()) {
          throw '';
        }
      } catch (err) {
        error = createError(util.format('The file at %s does not exist, or it is not a file.',
          filePath), err);
      }
    }
    // Now open a read stream on the file, and parse it.
    if (!error) {
      try {
        const stream = this._createReadStream(filePath);
        this.fromStream(stream, opt_callback);
      } catch (err) {
        error = createError(util.format('Unable to read the file at %s.', filePath), err);
      }
    }
    if (error) {
      callback(opt_callback, error);
    }
  }

  /**
   * Create a credentials instance using the given input options.
   * @param {object=} json The input object.
   * @param {function=} opt_callback Optional callback.
   */
  fromJSON (json, opt_callback) {
    let client;
    if (!json) {
      callback(opt_callback, new Error(
        'Must pass in a JSON object containing the Google auth settings.'));
      return;
    }
    if (json.type === 'authorized_user') {
      client = new this.UserRefreshClient();
    } else {
      client = new this.JWTClient();
    }
    client.fromJSON(json, (err) => {
      if (err) {
        callback(opt_callback, err);
      } else {
        callback(opt_callback, null, client);
      }
    });
  }

  /**
   * Create a credentials instance using the given input stream.
   * @param {object=} stream The input stream.
   * @param {function=} opt_callback Optional callback.
   */
  fromStream (stream, opt_callback) {
    if (!stream) {
      process.nextTick(() => {
        callback(opt_callback, new Error(
            'Must pass in a stream containing the Google auth settings.'));
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
        callback(opt_callback, err);
      }
    });
  }

  /**
   * Determines whether the current operating system is Windows.
   * @api private
   * */
  _isWindows () {
    const sys = this._osPlatform();
    if (sys && sys.length >= 3) {
      if (sys.substring(0, 3).toLowerCase() === 'win') {
        return true;
      }
    }
    return false;
  }

  /**
   * Creates a file stream. Allows mocking.
   * @api private
   * */
  _createReadStream (filePath) {
    return fs.createReadStream(filePath);
  }

  /**
   * Gets the value of the environment variable with the given name. Allows mocking.
   * @api private
   * */
  _getEnv (name) {
    return process.env[name];
  }

  /**
   * Gets the current operating system platform. Allows mocking.
   * @api private
   * */
  _osPlatform () {
    return os.platform();
  }

  /**
   * Determines whether a file exists. Allows mocking.
   * @api private
   * */
  _fileExists (filePath) {
    return fs.existsSync(filePath);
  }

  /**
   * Joins two parts of a path. Allows mocking.
   * @api private
   * */
  _pathJoin (item1, item2) {
    return path.join(item1, item2);
  }

  /**
   * Allows mocking of the path to a well-known file.
   * @api private
   * */
  _mockWellKnownFilePath (filePath) {
    return filePath;
  }
}

Object.defineProperties(GoogleAuth.prototype, {
  /**
   * Caches a value indicating whether the auth layer is running on Google Compute Engine.
   * @private
   */
  _isGCE: {
    configurable: true,
    writable: true,
    value: false
  },

  /**
   * Caches a value indicating whether we've checked whether the auth layer is running on
   * Google Compute Engine.
   * @private
   */
  _checked_isGCE: {
    configurable: true,
    writable: true,
    value: false
  }
});

/**
 * Export GoogleAuth.
 */
module.exports = GoogleAuth;
