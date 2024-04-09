const searchService = require('../service/SearchService');

class SearchController {
    async search(request, response) {
        const filters = request.body.filters;
        const sort_by = request.body.sort_by;
        const result = await searchService.getRestaurants(filters, sort_by);
        response.status(result.status).json(result);
    }
}

module.exports = new SearchController();