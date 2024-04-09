const axios = require('axios');
const {YELP} = require('../config/config')

class SearchService {
    async getRestaurants(filters, sort_by) {
        try{
            const yelp_url = `https://api.yelp.com/v3/businesses/search`;
            const result = await axios.get(yelp_url, {
                headers: {
                    'Authorization': `Bearer ${YELP.API_KEY}`
                },
                params: {
                    location: filters.location,
                    sort_by: sort_by,
                    limit: 20
                }
            });
            return {
                status: 200,
                data: result.data
            }
        } catch(err) {
            console.error(err);
            return {
                status: 500,
                error: 'Internal server error'
            }; 
        }
    }
}

module.exports = new SearchService();
