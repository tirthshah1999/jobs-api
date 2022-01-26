const jwt = require("jsonwebtoken");
const {UnauthenticatedError} = require("../errors"); 

const auth = async(req, res, next) => {
    // check header
    const authHeader = req.headers.authorization;
    if(!authHeader || !authHeader.startsWith("Bearer ")){
        throw new UnauthenticatedError("Authentication Invalid");
    }

    const token = authHeader.split(" ")[1];
    try {
        const payload = jwt.verify(token, process.env.JWT_SECRET);
        // attach the user to job routes so authorized user can access job
        // while creating jwt we are passing in payload as id, name so we are just catching here. 
        req.user = {userId: payload.userId, name: payload.name};
        next();
    } catch (error) {
        throw new UnauthenticatedError("Authentication Invalid");
    }  
}

module.exports = auth;