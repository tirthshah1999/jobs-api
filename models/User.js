const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const UserSchema = new mongoose.Schema({
    name:{
        type: String,
        required: [true, "Please provide name"],
        maxlength: 50,
        minlength: 3
    },
    email:{
        type: String,
        required: [true, "Please provide email"],
        match: [
            /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/,
            'Please provide a valid email',
        ],
        unique: true    // unique is not a validator
    },
    password: {
        type: String,
        required: [true, 'Please provide password'],
        minlength: 6,
    },
})

UserSchema.pre('save', async function(){    // this is pointing to our user document
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
});

UserSchema.methods.comparePassword = function(candidatePassword){
    const isMatch = bcrypt.compare(candidatePassword, this.password); // password is hashed in doc
    return isMatch;
}

UserSchema.methods.createJWT = function(){
    return jwt.sign(
        {userId: this._id, name: this.name},
        process.env.JWT_SECRET,
        {expiresIn: process.env.JWT_LIFETIME}
    )
}

module.exports = mongoose.model('User', UserSchema);