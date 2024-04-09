const axios = require('axios');
const {YELP} = require('../config/config')

class DetailsService {
    async getRestaurantDetails(restaurantId) {
        try{
            const yelp_url = `https://api.yelp.com/v3/businesses/${restaurantId}`;
            const result = await axios.get(yelp_url, {
                headers: {
                    'Authorization': `Bearer ${YELP.API_KEY}`
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

module.exports = new DetailsService();
