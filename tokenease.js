const jwt = require('jsonwebtoken');

// Middleware function to authenticate JWT tokens
const authenticateToken = (secretKey) => (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Unauthorized: Missing token' });
    }

    jwt.verify(token, secretKey, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Forbidden: Invalid token' });
        }
        req.user = user;
        next();
    });
};

// Function to generate JWT token
const generateToken = (payload, secretKey, expiresIn = '1h') => {
    return jwt.sign(payload, secretKey, { expiresIn });
};

// Function to generate JWT token with encrypted payload
const generateEncryptionToken = (payload, secretKey, encryptionKey, expiresIn = '1h') => {
    // Encrypt the payload
    const cipher = crypto.createCipheriv('aes-256-cbc', encryptionKey, Buffer.alloc(16, 0));
    let encryptedPayload = cipher.update(JSON.stringify(payload), 'utf8', 'base64');
    encryptedPayload += cipher.final('base64');

    // Generate JWT token with encrypted payload
    const token = jwt.sign({ payload: encryptedPayload }, secretKey, { expiresIn });
    return token;
};

// Function to verify JWT token and decrypt payload
const verifyEncryptionToken = (token, secretKey, encryptionKey) => {
    try {
        const decodedToken = jwt.verify(token, secretKey);
        if (decodedToken && decodedToken.payload) {
            // Decrypt the payload
            const decipher = crypto.createDecipheriv('aes-256-cbc', encryptionKey, Buffer.alloc(16, 0));
            let decryptedPayload = decipher.update(decodedToken.payload, 'base64', 'utf8');
            decryptedPayload += decipher.final('utf8');
            return JSON.parse(decryptedPayload);
        } else {
            throw new Error('Invalid token format');
        }
    } catch (error) {
        throw new Error('Invalid token or decryption failed');
    }
};

// Function to generate a new access token using a refresh token
const refreshAccessToken = (refreshToken, secretKey, extractUser) => {
    return new Promise((resolve, reject) => {
        jwt.verify(refreshToken, secretKey, (err, decoded) => {
            if (err) {
                return reject(err);
            }
            const user = extractUser(decoded);
            if (!user) {
                return reject(new Error('Invalid user extracted from refresh token'));
            }
            const accessToken = generateToken(user, secretKey);
            resolve(accessToken);
        });
    });
};

// Function to revoke or blacklist a token
const blacklistToken = (tokenIdentifier, schemaClass) => {
    return new Promise((resolve, reject) => {
        schemaClass.deleteOne({ tokenIdentifier }, (err, result) => {
            if (err) {
                return reject(err);
            }
            resolve(result.deletedCount > 0);
        });
    });
};


// Function to revoke all tokens associated with a user
const revokeUserTokens = (userId, schemaClass) => {
    return new Promise((resolve, reject) => {
        schemaClass.deleteMany({ userId }, (err, result) => {
            if (err) {
                return reject(err);
            }
            resolve(result.deletedCount > 0);
        });
    });
};

// Function to revoke a specific token by its identifier
const revokeTokenByIdentifier = (tokenIdentifier, schemaClass) => {
    return new Promise((resolve, reject) => {
        schemaClass.deleteOne({ tokenIdentifier }, (err, result) => {
            if (err) {
                return reject(err);
            }
            resolve(result.deletedCount > 0);
        });
    });
};
// Function to handle token expiry
const handleTokenExpiry = (accessToken, refreshToken, secretKey, extractUser) => {
    return new Promise((resolve, reject) => {
        jwt.verify(accessToken, secretKey, (err, decoded) => {
            if (err) {
                // Access token has expired
                if (err.name === 'TokenExpiredError') {
                    // If access token is expired, try refreshing it using the refresh token
                    refreshAccessToken(refreshToken, secretKey, extractUser)
                        .then((newAccessToken) => {
                            resolve(newAccessToken);
                        })
                        .catch((refreshErr) => {
                            reject(refreshErr);
                        });
                } else {
                    // Other errors during token verification
                    reject(err);
                }
            } else {
                // Access token is still valid
                resolve(accessToken);
            }
        });
    });
};



module.exports = {
    authenticateToken,
    generateToken,
    refreshAccessToken,
    blacklistToken,
    revokeUserTokens,
    revokeTokenByIdentifier,
    handleTokenExpiry,
     generateEncryptionToken,
    verifyEncryptionToken
};

