const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const serverless = require('serverless-http');
const {authenticateToken} = require('./auth/AuthToken');

const app = express();

app.use(cors())
app.use(bodyParser.json());

const userController = require('./controller/UserController');
const searchController = require('./controller/SearchController');
const detailsController = require('./controller/DetailsController');
const reservationController = require('./controller/ReservationController');

// Signup route
app.post('/auth/signup', userController.signup);

// Login route
app.post('/auth/signin', userController.signin);

// Subscription service
app.post('/subscribe', authenticateToken, userController.subscribeEmail);

// Search service
app.post('/restaurant/search', authenticateToken, searchController.search);

// Details service
app.post('/restaurant/details', authenticateToken, detailsController.details);

// Reservation service
app.post('/restaurant/reservation', authenticateToken, reservationController.reserve);

// Get Reservations service
app.post('/reservations', authenticateToken, reservationController.getReservations);

// Cancel Reservation service
app.post('/cancel-reservation', authenticateToken, reservationController.cancelReservation);

// // const PORT = 3000;
// // app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

module.exports.handler = serverless(app);
