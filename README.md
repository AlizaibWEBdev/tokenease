# Express JWT Library tokenease


===================

This library provides easy-to-use functions for handling JWT (JSON Web Token) authentication in Express.js applications. It simplifies token authentication, generation, refreshing, and revocation, making it more convenient for developers to implement JWT-based authentication in their projects.

Installation
------------

To use this library, you need to install it via npm:

    npm install tokenease

Usage
-----

Below are the functions provided by this library:

### authenticateToken(secretKey)

Middleware function to authenticate JWT tokens.

*   **secretKey:** The secret key used to verify JWT tokens.

         const { authenticateToken } = require('tokenease');
    
    app.use(authenticateToken('your_secret_key'));

### generateToken(payload, secretKey, expiresIn = '1h')

Function to generate a JWT token.

*   **payload:** Data to be included in the token.
*   **secretKey:** The secret key used to sign the token.
*   **expiresIn:** Expiry duration for the token (default is 1 hour).

         const { generateToken } = require('tokenease');
    
         const token = generateToken({ userId: '123456' }, 'your_secret_key');

### refreshAccessToken(refreshToken, secretKey, extractUser)

Function to generate a new access token using a refresh token.

*   **refreshToken:** The refresh token used to generate a new access token.
*   **secretKey:** The secret key used to verify tokens.
*   **extractUser:** Function to extract user data from the refresh token.

         const { refreshAccessToken } = require('tokenease');
    
        refreshAccessToken(refreshToken, 'your_secret_key', (decoded) => decoded.user);

### blacklistToken(tokenIdentifier, schemaClass)

Function to revoke or blacklist a token.

*   **tokenIdentifier:** Identifier of the token to be blacklisted.
*   **schemaClass:** Schema class for interacting with the database.

         const { blacklistToken } = require('tokenease');
    
         blacklistToken(tokenIdentifier, YourSchemaClass)
         .then((success) => {
        console.log('Token blacklisted:', success);
        })
        .catch((error) => {
        console.error('Error blacklisting token:', error);
        });

### revokeUserTokens(userId, schemaClass)

Function to revoke all tokens associated with a user.

*   **userId:** ID of the user whose tokens need to be revoked.
*   **schemaClass:** Schema class for interacting with the database.

         const { revokeUserTokens } = require('tokenease');
    
        revokeUserTokens(userId, YourSchemaClass)
        .then((success) => {
         console.log('Tokens revoked:', success);
        })
        .catch((error) => {
        console.error('Error revoking tokens:', error);
        });

### revokeTokenByIdentifier(tokenIdentifier, schemaClass)

Function to revoke a specific token by its identifier.

*   **tokenIdentifier:** Identifier of the token to be revoked.
*   **schemaClass:** Schema class for interacting with the database.

         const { revokeTokenByIdentifier } = require('tokenease');
         revokeTokenByIdentifier(tokenIdentifier, YourSchemaClass).then((success) => {
         console.log('Token revoked:', success);
        })
        .catch((error) => {
        console.error('Error revoking token:', error);
        });

### handleTokenExpiry(accessToken, refreshToken, secretKey, extractUser)

Function to handle token expiry by refreshing access tokens using refresh tokens.

*   **accessToken:** The access token to be verified.
*   **refreshToken:** The refresh token used to refresh the access token.
*   **secretKey:** The secret key used to verify tokens.
*   **extractUser:** Function to extract user data from the refresh token.

         const { handleTokenExpiry } = require('tokenease');
    
        handleTokenExpiry(accessToken, refreshToken, 'your_secret_key', (decoded) => decoded.user)
        .then((newAccessToken) => {
        console.log('New access token:', newAccessToken);
        }).catch((error) => {
        console.error('Error handling token expiry:', error);
        });


# JWT Encryption Token Functions

This document describes two additional functions added to the JWT authentication library: `generateEncryptionToken` and `verifyEncryptionToken`. These functions enable developers to generate and verify JWT tokens with encrypted payloads, enhancing the security of token-based authentication in Express.js applications.

## generateEncryptionToken

### Description

The `generateEncryptionToken` function generates a JWT token with an encrypted payload. This function encrypts the provided payload using AES-256-CBC encryption and signs the JWT token with the encrypted payload. Developers can specify the secret key, encryption key, expiration time, and payload when calling this function.

### Syntax


```
generateEncryptionToken(payload, secretKey, encryptionKey, [expiresIn])
```


*   **payload:** The payload object to be encrypted and included in the JWT token.
*   **secretKey:** The secret key used for signing the JWT token.
*   **encryptionKey:** The encryption key used to encrypt the payload.
*   **expiresIn:** (optional) The expiration time for the JWT token (default: '1h')

## exemple 
```
const token = generateEncryptionToken({ userId: '123', role: 'admin' }, 'mySecretKey', 'encryptionSecret');
```

## verifyEncryptionToken

The verifyEncryptionToken function verifies a JWT token with an encrypted payload and decrypts the payload. This function checks the validity of the token signature using the provided secret key and then decrypts the encrypted payload using the specified encryption key. If the token is valid and the payload decryption is successful, the function returns the decrypted payload.

# sayntax 

```verifyEncryptionToken(token, secretKey, encryptionKey)```

* **token:** The JWT token to be verified and decrypted.
* **secretKey:** The secret key used for verifying the JWT token signature.
* **encryptionKey:** The encryption key used to decrypt the payload.

## exemple 

```
const payload = verifyEncryptionToken(token, 'mySecretKey', 'encryptionSecret'); 
console.log(payload); // { userId: '123', role: 'admin' }
```



This library is licensed under the MIT License.


