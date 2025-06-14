const mongoose = require('mongoose');
const crypto = require("crypto");

const Userschema = new mongoose.Schema({
    username: { type: String, required: true , unique: true},
    email:    { type: String, required: true, unique: true },
    password: { type: String, required: true },
    resetToken: String,
    resetTokenExpiration: Date,
    master_password: { type: String },
});
const User = mongoose.model("user2", Userschema);
module.exports = User;
