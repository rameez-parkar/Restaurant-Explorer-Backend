const userService = require('../service/UserService');

class UserController {
    async signup(request, response) {
        const userDetails = request.body;
        const result = await userService.signup(userDetails);
        response.status(result.status).json(result);
    }

    async signin(request, response) {
        const credentials = request.body;
        const result = await userService.signin(credentials);
        response.status(result.status).json(result);
    }

    async subscribeEmail(request, response) {
        const emailAddress = request.body.userEmail;
        const result = await userService.subscribeEmail(emailAddress);
        response.status(result.status).json(result);
    }
}

module.exports = new UserController();