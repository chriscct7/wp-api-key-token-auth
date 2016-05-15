# WP API Key Token Authentication #

### Welcome to our GitHub Repository

This plugin implements a Token/Key/Secret based Authentication method for the WordPress REST API

It is compatible with the REST Console and REST Logger plugins.

## Installation ##

Note: This plugin requires PHP 5.2 or newer, and requires the [WP REST API V2](https://github.com/WP-API/WP-API) version 2 or newer

1. You can clone the GitHub repository: `https://github.com/chriscct7/wp-api-key-token-auth.git`
2. Or download it directly as a ZIP file: `https://github.com/chriscct7/wp-api-key-token-auth/archive/master.zip`

This will download the latest developer copy of WP API Key Token Authentication.

## Bugs ##
If you find an issue, let us know [here](https://github.com/chriscct7/wp-api-key-token-auth/issues?state=open)!

## Support ##
This is a developer's portal for WP API Key Token Authentication and should _not_ be used for support.

## Contributions ##
Anyone is welcome to contribute to WP API Key Token Authentication. Please read the [guidelines for contributing](https://github.com/chriscct7/wp-api-key-token-auth/blob/master/CONTRIBUTING.md) to this repository.

There are various ways you can contribute:

1. Raise an [Issue](https://github.com/chriscct7/wp-api-key-token-auth/issues) on GitHub
2. Send us a Pull Request with your bug fixes and/or new features
3. Translate WP API Key Token Authentication into different languages
4. Provide feedback and suggestions on [enhancements](https://github.com/chriscct7/wp-api-key-token-auth/issues?direction=desc&labels=Enhancement&page=1&sort=created&state=open)

## How It Works ##

This project works as a custom authentication route for the WordPress REST API introduced in WordPress 4.4.

### Quick Overview ###
* Create a token by sending username and password in the body of a request to:
    `mysite.com/wp-json/auth/v1/token/generate`
* If token already exists send usermame and password to:
    `mysite.com/wp-json/auth/v1/token/retrieve`
* Once a token and public key are acquired, send them in x-wp-auth-key and x-wp-auth-token headers to make authenticated requests.
* See the examples, and detailed explanation below.
* You should probably use HTTPS to mitigate the risk of MitM attacks.

### Detailed Overview ###

In order to authenticate as a user, a public token and key must be obtained. To obtain a token for a user, a POST request of the WordPress username and password can be sent to mysite.com/wp-json/auth/v1/token/retrieve, which will return a json encoded array of the user's public token, public key, and user ID if the token exists. If the username and/or password is wrong, a 403 HTTP status error will be returned explaining such. If the user does not have a key/token pair, a 403 HTTP status error will be returned saying such.

If a user does not have an issued key/token pair, one can be obtained by sending a POST request of the WordPress username and password  to mysite.com/wp-json/auth/v1/token/generate. If the username and/or password is wrong, a 403 HTTP status error will be returned explaining such. If the user already has a key/token pair, a 403 HTTP status error will be returned saying such.

If you need to validate a key/token pair is still valid, a POST request can be sent to  mysite.com/wp-json/auth/v1/token/validate using HTTP basic auth headers of the public token for the username and the public key for the password. If the key and/or token is wrong, a 403 HTTP status error will be returned explaining such. 

Further, key/token pairs can be revoked by sending a POST request to  mysite.com/wp-json/auth/v1/token/validate using HTTP basic auth headers of the public token for the username and the public key for the password. In addition, a key/token pair can be regenerated (old pair revoked, new pair generated ) by sending a POST request to  mysite.com/wp-json/auth/v1/token/validate using HTTP basic auth headers of the public token for the username and the public key for the password with a return of a json encoded array containing the new key and token and the user id.

Our project also considers large website needs by utilizing a WordPress standard database cache layer to make the authentication route more performant.

Finally, our project also allows admins in the WordPress backend to see a table listing all outstanding combinations, and the users they are for. From the table, an admin can add/revoke/regenerate pairs, as well as search for pairs for a user by username. Additionally, these options are available to administrators on a user by user basis on the WordPress edit user screen for a given user, as well as on the profile page for the currently logged in user.

The public key is generated via an md5 hashs of the user email concatenated with the auth_key (a constant string defined by WordPress that is 256 unique characters and varies on every install) concatenated with the unix timestamp at the generation runtime.

The private key similarly is generated identically.

The public token is generated via an MD5 hash of the secret key and the public key concatenated (in that order).

Thus verification is done by hash_equals( md5( $secret . $public ), $token ) (using hash_equals as opposed to === to avoid string comparison timing attacks).

Note: In order to facilitate sharing this part of my senior project, this project was moved from a private WordPress repository used for the whole senior project to a public, and in the process, git history is not available for this repository. Linus Thorvalds sends his regards: https://github.com/torvalds/linux/pull/17#issuecomment-5654674.

Note: Included screenshots show some of the WP API Key Token Authentication endpoints, as well as the administration area.

Note: This was tested on a copy of WordPress pre-API infrastructure merge, using a pre-API infrastructure merge copy of WP-API plugin. It has not been tested since.


## Examples ##

Get public key and token via jQuery AJAX:

```
    var settings = {
      "async": true,
      "crossDomain": true,
      "url": "http://hiroy.club/wp-json/auth/v1/token",
      "method": "POST",
      "headers": {
        "content-type": "application/x-www-form-urlencoded"
      },
      "data": {
        "username": "admin",
        "password": "12345"
      }
    }
    
    $.ajax(settings).done(function (response) {
      var key: response.public_key;
      var token: response.token;
    });
```


Use key/token to edit post 1:


```
    var settings = {
      "async": true,
      "crossDomain": true,
      "url": "http://local.wordpress-trunk.dev/wp-json/wp/v2/posts/1",
      "method": "GET",
      "headers": {
        "cache-control": "no-cache",
        "authorization": "Basic MjJhMTYyYjJiMTUwZWE5ZDZhZGVjMzI2N2U4NDJmZmI6N2FlMDBkMzIxNjk1NjU5MTRjMmE3NTE0ZDkxM2M0YzM=",      }
    }
    
    $.ajax(settings).done(function (response) {
      console.log(response);
    });
```
