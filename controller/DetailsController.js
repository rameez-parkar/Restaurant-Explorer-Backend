const detailsService = require('../service/DetailsService');

class DetailsController {
    async details(request, response) {
        const restaurantId = request.body.restaurantId;
        const result = await detailsService.getRestaurantDetails(restaurantId);
        response.status(result.status).json(result);
    }
}

module.exports = new DetailsController();