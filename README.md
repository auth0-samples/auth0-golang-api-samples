# Auth0 Golang API Samples

> :warning:  **Important security note:** This solution uses a 3rd party library with an unresolved [security issue](https://cve.mitre.org/cgi-bin/cvename.cgi?name=2020-26160). Please review the details of the vulnerability, including any of the documented mitigations, before implementing the solution.

[![CircleCI](https://img.shields.io/circleci/project/github/auth0-samples/auth0-golang-api-samples.svg?style=flat-square)](https://circleci.com/gh/auth0-samples/auth0-golang-api-samples/tree/master)

These samples demonstrate how to create an API with Go which only permits access to resources if a valid **access token** is included. This verification is done by validating the signature and claims in a JSON Web Token (JWT) signed by Auth0.

These samples do not demonstrate how to sign a JWT but rather assume that a user has already been authenticated by Auth0 and holds an access token for API access. For information on how to use Auth0 to authenticate users, see [the docs](https://auth0.com/docs).

## What is Auth0?

Auth0 helps you to:

* Add authentication with [multiple authentication sources](https://docs.auth0.com/identityproviders), either social like **Google, Facebook, Microsoft Account, LinkedIn, GitHub, Twitter, Box, Salesforce, amont others**, or enterprise identity systems like **Windows Azure AD, Google Apps, Active Directory, ADFS or any SAML Identity Provider**.
* Add authentication through more traditional **[username/password databases](https://docs.auth0.com/mysql-connection-tutorial)**.
* Add support for **[linking different user accounts](https://docs.auth0.com/link-accounts)** with the same user.
* Support for generating signed [Json Web Tokens](https://docs.auth0.com/jwt) to call your APIs and **flow the user identity** securely.
* Analytics of how, when and where users are logging in.
* Pull data from other sources and add it to the user profile, through [JavaScript rules](https://docs.auth0.com/rules).

## Create a free Auth0 account

1. Go to [Auth0](https://auth0.com/signup) and click Sign Up.
2. Use Google, GitHub or Microsoft Account to login.

## Issue Reporting

If you have found a bug or if you have a feature request, please report them at this repository issues section. Please do not report security vulnerabilities on the public GitHub issue tracker. The [Responsible Disclosure Program](https://auth0.com/whitehat) details the procedure for disclosing security issues.

## Author

[Auth0](auth0.com)

## License

This project is licensed under the MIT license. See the [LICENSE](LICENSE.txt) file for more info.
