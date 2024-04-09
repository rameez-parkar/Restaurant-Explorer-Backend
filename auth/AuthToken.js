const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const {db} = require('../database/database');

const generatedSecretKey = crypto.randomBytes(3).toString('hex').toUpperCase();

async function authenticateToken(request, response, next) {
    try {
        const token = request.headers['authorization'];
        const userEmail = request.method === "POST" ? request.body.userEmail : request.query.email;
    
        const [rows] = await db.execute('SELECT secretKey FROM users WHERE email = ?', [userEmail]);
    
        if (!token || rows.length === 0) {
            return response.status(401).json({ 
                status: 401,
                error: 'Unauthorized'
            });
        }
            
        jwt.verify(token.split(' ')[1], rows[0].secretKey, (err, decoded) => {
            if (err) {
                return response.status(403).json({
                    status: 403,
                    error: 'Invalid auth token'
                });
            }
            request.user = decoded;
            next();
        });
    } catch(err) {
        return response.status(500).json({
            status: 500,
            error: 'Internal Server Error'
        });
    }
}

function generateToken(user) {
    return {
        token: jwt.sign(user, generatedSecretKey),
        secretKey: generatedSecretKey
    }
}

module.exports.authenticateToken = authenticateToken;
module.exports.generateToken = generateToken;
