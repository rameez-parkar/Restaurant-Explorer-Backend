const { AWS_AUTH } = require('../config/config');
const { db } = require('../database/database');
const AWS = require("@aws-sdk/client-sns");
const sns = new AWS.SNS();

class ReservationService {
    async reserve(reservationDetails) {
        try {                
            await db.execute(
                `CREATE TABLE IF NOT EXISTS reservations (
                    id INT AUTO_INCREMENT PRIMARY KEY, 
                    email VARCHAR(255) NOT NULL,
                    restaurantId VARCHAR(255) NOT NULL,
                    restaurantName VARCHAR(255) NOT NULL,
                    reservationTimestamp VARCHAR(255) NOT NULL)`
            );
            const [rows] = await db.execute('SELECT * FROM users WHERE email = ?', [reservationDetails.userEmail]);
            if (rows.length === 0) {
                return {
                    status: 400,
                    error: 'User not found'
                };
            }

            await db.execute('INSERT INTO reservations (email, restaurantId, restaurantName, reservationTimestamp) VALUES (?, ?, ?, ?)',
                [reservationDetails.userEmail, reservationDetails.restaurantId, reservationDetails.restaurantName, reservationDetails.reservationTimestamp]);

            const [reservationRows] = await db.execute('SELECT * FROM reservations WHERE email = ? AND restaurantId = ?', [reservationDetails.userEmail, reservationDetails.restaurantId]);

            if (reservationRows.length === 0) {
                return {
                    status: 500,
                    error: 'Reservation failed!'
                };
            }

            await this.emailBookingDetails(reservationRows[reservationRows.length - 1]);

            return { 
                status: 200,
                message: `Reservation successful!`,
                reservationId: reservationRows[reservationRows.length - 1].id,
                restaurantName: reservationRows[reservationRows.length - 1].restaurantName,
                reservationTimestamp: reservationRows[reservationRows.length - 1].reservationTimestamp,
                reservedByName: rows[0].name
            };
        } catch (err) {
            console.error(err);
            return {
                status: 500,
                error: 'Internal server error'
            };
        }
    }

    async emailBookingDetails(reservation) {
        const params = {
            Message: `Hello Customer\n\nYour reservation at ${reservation.restaurantName} is confirmed for ${this.formatDate(+reservation.reservationTimestamp)} ${this.formatTime(+reservation.reservationTimestamp)}.\n\nYour Reservation ID is ${reservation.id}.`,
            Subject: `Reservation at ${reservation.restaurantName}`,
            TopicArn: AWS_AUTH.SNS.TOKEN_ARN
        };

        try {
            console.log(params.Message);
            const response = await sns.publish(params);
            console.log('Message sent:', response.MessageId);
            return {
                statusCode: 200,
                body: 'Email sent successfully'
            };
        } catch (err) {
            console.error('Error sending message:', err);
            return {
                statusCode: 500,
                body: 'Error sending email'
            };
        }
    }

    formatDate(timestamp) {
        const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
        const dateObj = new Date(timestamp);
        const formattedDate = dateObj.toLocaleDateString('en-US', { timeZone: timezone });
        return formattedDate;
    }
    
    formatTime(timestamp) {
        const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
        const dateObj = new Date(timestamp);
        const formattedTime = dateObj.toLocaleTimeString('en-US', { timeZone: timezone });
        return formattedTime;
    }

    async getReservations(email) {
        try {
            const [reservationRows] = await db.execute('SELECT * FROM reservations WHERE email = ?', [email]);

            return { 
                status: 200,
                data: reservationRows
            };
        }  catch(err) {
            console.error(err);
            return {
                status: 500,
                error: 'Internal server error'
            };
        }
    }

    async cancelReservation(email, id) {
        try {
            await db.execute('DELETE FROM reservations WHERE email = ? AND id = ?', [email, id]);

            return { 
                status: 200,
                message: `Reservation ID ${id} has been cancelled.`
            };
        }  catch(err) {
            console.error(err);
            return {
                status: 500,
                error: 'Internal server error'
            };
        }
    }
}

module.exports = new ReservationService();
