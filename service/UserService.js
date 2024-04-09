const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { db } = require('../database/database');
const {generateToken} = require('../auth/AuthToken');
const { AWS_AUTH } = require('../config/config');
const AWS = require("@aws-sdk/client-sns");

class UserService {
    async signup(userDetails) {
        try {                
            await db.execute(
                `CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY, 
                    email VARCHAR(255) NOT NULL, 
                    password VARCHAR(255) NOT NULL, 
                    name VARCHAR(255) NOT NULL, 
                    phone VARCHAR(255) NOT NULL, 
                    address VARCHAR(255) NOT NULL, 
                    secretKey VARCHAR(255))`
            );
            const [rows] = await db.execute('SELECT * FROM users WHERE email = ?', [userDetails.email]);
            if (rows.length > 0) {
                return {
                    status: 400,
                    error: 'User already exists'
                };
            }

            const salt = await bcrypt.genSalt(10);
            const hashedPassword = await bcrypt.hash(userDetails.password, salt);

            await db.execute('INSERT INTO users (email, password, name, phone, address, secretKey) VALUES (?, ?, ?, ?, ?, ?)',
                [userDetails.email, hashedPassword, userDetails.name, userDetails.phone, userDetails.address, null]);

            return { 
                status: 200,
                message: 'Signup Successful!'
            };
        } catch (err) {
            console.error(err);
            return {
                status: 500,
                error: 'Internal server error'
            };
        }
    }

    async signin(credentials) {
        try {
            const [rows] = await db.execute('SELECT * FROM users WHERE email = ?', [credentials.email]);
            if (rows.length === 0) {
                return {
                    status: 400,
                    error: 'Invalid credentials'
                }
            }

            const passwordValid = await bcrypt.compare(credentials.password, rows[0].password);

            if (!passwordValid) {
                return { 
                    status: 400,
                    error: 'Invalid credentials' 
                };
            }

            const {token, secretKey} = generateToken({ 
                email: rows[0].email,
                name: rows[0].name
            });

            await db.execute('UPDATE users SET secretKey = ? WHERE email = ?', [secretKey, rows[0].email])

            return {
                status: 200,
                message: 'Signin Successful!',
                token: token,
                email: rows[0].email
            }

        } catch(err) {
            console.error(err);
            return {
                status: 500,
                error: 'Internal server error'
            };
        }
    }

    async subscribeEmail(emailAddress) {
        const params = {
            Protocol: 'email',
            TopicArn: AWS_AUTH.SNS.TOKEN_ARN,
            Endpoint: emailAddress
        };
    
        try {
            const sns = new AWS.SNS();
            const response = await sns.subscribe(params);
            console.log('Subscription ARN:', response.SubscriptionArn);
            return {
                status: 200,
                subscriptionArn: response.SubscriptionArn
            }
        } catch (err) {
            console.error('Error subscribing email address:', err);
            return {
                status: 500,
                error: 'Internal Server Error'
            }
        }
    }
}

module.exports = new UserService();
