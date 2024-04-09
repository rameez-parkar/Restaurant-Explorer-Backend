const reservationService = require('../service/ReservationService');

class ReservationController {
    async reserve(request, response) {
        const reservationDetails = request.body;
        const result = await reservationService.reserve(reservationDetails);
        response.status(result.status).json(result);
    }

    async getReservations(request, response) {
        const email = request.body.userEmail;
        const result = await reservationService.getReservations(email);
        response.status(result.status).json(result);
    }

    async cancelReservation(request, response) {
        const email = request.body.userEmail;
        const id = request.body.id;
        const result = await reservationService.cancelReservation(email, id);
        response.status(result.status).json(result);
    }
}

module.exports = new ReservationController();