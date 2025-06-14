const mongoose = require('mongoose');

const PasswordSchema = new mongoose.Schema({
    userId: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'user2', 
        required: true 
    },
    website: { 
        type: String, 
        required: true 
    },
    website_url:{
        type: String,
        required: true
    },
    username: { 
        type: String, 
        required: true 
    },
    password: {
        ciphertext: [Number],
        iv: [Number],
        salt: [Number]
    },
    notes: { 
        type: String, 
        default: '' 
    },
    createdAt: { 
        type: Date, 
        default: Date.now 
    },
    updatedAt: { 
        type: Date, 
        default: Date.now 
    }
});


const Password = mongoose.model("Password", PasswordSchema);
module.exports = Password;
