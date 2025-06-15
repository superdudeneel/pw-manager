const http = require('http');
const express = require("express");
const mongoose = require("mongoose");
const path = require('path');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const dotenv = require('dotenv');
const nodemailer = require('nodemailer');

const User = require('./models/Usermodel');
const Password = require('./models/Passwordmodel');


dotenv.config();

const session = require('express-session');
const MongoStore = require('connect-mongo');



const app = express();
const port = 8000;

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.MAIL,
      pass: process.env.YOUR_APP_PASS  // Not your Gmail password! Use an App Password.
    }
});

app.use(session({
    secret: 'your-secret-key', // Change this to a random string
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ 
        mongoUrl: process.env.MONGO_URL
    }),
    cookie: { 
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

mongoose
    .connect(process.env.MONGO_URL, {
        useNewUrlParser: true,
        useUnifiedTopology: true
    })
    .then(()=>{
        console.log("mongo db connected");
    })
    .catch((err)=>{
        console.log("Error", err);
    })

// User Schema


// Password Schema - NEW


app.use((req, res, next) => {
    res.locals.user = req.session.user || null;
    next();
});

app.use(express.urlencoded({extended : false})); 
app.use(express.json());
app.use(express.static('templates'));
app.use(express.static('public'));

app.get("/", (req, res)=>{
    return res.sendFile(path.join(__dirname, 'templates/index.html'));
});

app.get('/app', (req, res)=>{
    if (!req.session.user) {
        return res.redirect('/login');
    }
    return res.sendFile(path.join(__dirname, 'templates/home.html'));
})

app.get('/email-sent', (req, res)=>{
    return res.sendFile(path.join(__dirname, 'templates/email-sent.html'));
})

app.get('/login', (req, res)=>{
    if(req.session.user){
        return res.redirect('/app')
    }
    return res.sendFile(path.join(__dirname, 'templates/login.html'));
})

app.get('/signup', (req, res)=>{
    if(req.session.user){
        return res.redirect('/app');
    }
    return res.sendFile(path.join(__dirname, 'templates/signup.html'));
})

app.get('/forgot-pass', (req, res)=>{
    if(req.session.user){
        return res.redirect('/app');
    }
    return res.sendFile(path.join(__dirname, 'templates/forgot-password.html'));
})

// Modified route to handle token verification
app.get('/reset-pass', async (req, res)=>{
    const { token } = req.query;
    
    if (!token) {
        return res.send('Invalid or missing reset token. <a href="/forgot-pass">Request a new reset link</a>');
    }

    try {
        // Find user with valid token that hasn't expired
        const user = await User.findOne({
            resetToken: token,
            resetTokenExpiration: { $gt: Date.now() }
        });

        if (!user) {
            return res.send('Invalid or expired reset token. <a href="/forgot-pass">Request a new reset link</a>');
        }

        // Token is valid, serve the reset password page
        return res.sendFile(path.join(__dirname, "templates/reset-password.html"));
    } catch (error) {
        console.error('Error verifying reset token:', error);
        return res.send('An error occurred. <a href="/forgot-pass">Try again</a>');
    }
})

// Alternative route name that matches your email link
app.get('/reset-password', async (req, res)=>{
    const { token } = req.query;
    
    if (!token) {
        return res.send('Invalid or missing reset token. <a href="/forgot-pass">Request a new reset link</a>');
    }

    try {
        // Find user with valid token that hasn't expired
        const user = await User.findOne({
            resetToken: token,
            resetTokenExpiration: { $gt: Date.now() }
        });

        if (!user) {
            return res.send('Invalid or expired reset token. <a href="/forgot-pass">Request a new reset link</a>');
        }

        // Token is valid, redirect to reset-pass with token
        return res.redirect(`/reset-pass?token=${token}`);
    } catch (error) {
        console.error('Error verifying reset token:', error);
        return res.send('An error occurred. <a href="/forgot-pass">Try again</a>');
    }
});

app.post('/signup', async (req, res)=>{
    const { username, email, password } = req.body;
    
    try {
        const newpassword = await bcrypt.hash(password, 10);
        await User.create({
            username,
            email,
            password: newpassword,
        });
        return res.redirect('/login');
    } catch (error) {
        console.error('Signup error:', error);
        return res.send('Error creating account. <a href="/signup">Try again</a>');
    }
});

app.post('/login', async (req, res)=>{
    const { username, password } = req.body;

    try {
        const user = await User.findOne({ username });

        if (!user) {
            return res.json({success: false, message: 'Invalid username'})
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);

        if (!isPasswordValid) {
            return res.json({success: false, message: 'Invalid password'});
        }

        req.session.user = {
                id: user._id,
                username: user.username,
                email: user.email,
        };

        if(user.master_password!=undefined){
            // Set a cookie with the username
            res.cookie('username', user.username, { 
                maxAge: 24 * 60 * 60 * 1000, // 24 hours
                httpOnly: false // So client-side JS can read it
            });
            res.cookie('email',user.email, { 
                maxAge: 24 * 60 * 60 * 1000,
                httpOnly: false
            });
            res.cookie('sessionID', req.sessionID, {
                maxAge: 24 * 60 * 60 * 1000,
                httpOnly: false
            })

            return res.json({ success: true, redirect: '/app' });
        }

        return res.json({ success: true, redirect: '/master-pass' });
    } catch (error) {
        console.error('Login error:', error);
        return res.send("An error occurred. <a href='/login'>Try again</a>");
    }
});

app.get('/master-pass', (req, res)=>{
    return res.sendFile(path.join(__dirname, 'templates/master-pass.html'));
})

app.post('/master-pass',async (req, res)=>{
    const {master_password} = req.body;
    const user = await User.findOne({username: req.session.user.username});
    const hashed_master_password = await bcrypt.hash(master_password, 10);
    
    await User.findByIdAndUpdate(user._id, {
        master_password: hashed_master_password,
    });

    // Set cookies with the new master_password
    res.cookie('username', user.username, { 
        maxAge: 24 * 60 * 60 * 1000,
        httpOnly: false
    });
    res.cookie('email', user.email, { 
        maxAge: 24 * 60 * 60 * 1000,
        httpOnly: false
    });
    res.cookie('sessionID', req.sessionID, {
        maxAge: 24 * 60 * 60 * 1000,
        httpOnly: false
    });

    return res.redirect('/app');
});

// Add logout route
app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.send('Error logging out');
        }
        // Clear all cookies
        res.clearCookie('username');
        res.clearCookie('email');
        res.clearCookie('sessionID');
        res.clearCookie('master_password');
        
        res.redirect('/login');
    });
});

app.post('/forgot-pass', async (req, res) => {
    const { email } = req.body;
    
    try {
        const user = await User.findOne({ email });

        if (!user) {
            return res.send('No account with that email found. <a href="/forgot-pass">Try again</a>');
        }

        // Generate reset token and set expiration (1 hour from now)
        const token = crypto.randomBytes(32).toString('hex');
        const resetTokenExpiration = Date.now() + 300000; // 5 minutes

        // Save token and expiration to user
        await User.findByIdAndUpdate(user._id, {
            resetToken: token,
            resetTokenExpiration: resetTokenExpiration
        });

        const resetLink = `http://localhost:8000/reset-password?token=${token}`;

        const mailoptions = {
            from: '"Neel from secure vault" <dudemrwonderful@gmail.com>',
            to: email,
            subject: 'password reset email',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2>Password Reset Request</h2>
                    <p>You requested a password reset for your account.</p>
                    <p>Click the link below to reset your password:</p>
                    <a href="${resetLink}" style="background-color: #667eea; color: white; padding: 12px 24px; text-decoration: none; border-radius: 8px; display: inline-block; margin: 20px 0;">Reset Password</a>
                    <p>This link will expire in 5 min.</p>
                    <p>If you didn't request this password reset, please ignore this email.</p>
                </div>
            `,
        }
        transporter.sendMail(mailoptions, (error, info) => {
            if (error) {
              return console.error('Error sending mail:', error);
            }
            return res.redirect('/email-sent');
        });
        
        
    } catch (error) {
        console.error('Forgot password error:', error);
        return res.send('An error occurred. <a href="/forgot-pass">Try again</a>');
    }
});

app.post('/app', async (req, res)=>{
    const {master_password} = req.body;
    const user = await User.findOne({username: req.session.user.username});
    const is_valid = await bcrypt.compare(master_password, user.master_password);
    if(is_valid){
        return res.json({success: true});
    }
    return res.json({success: false, message: 'Invalid master password'});
})

app.post('/reset-pass', async (req, res) => {
    const { token } = req.query;
    const { newPassword, confirmPassword } = req.body;

    try {
        if (!token) {
            return res.status(400).json({ 
                success: false, 
                message: 'Invalid or missing reset token.' 
            });
        }

        if (!newPassword || !confirmPassword) {
            return res.status(400).json({ 
                success: false, 
                message: 'Both password fields are required.' 
            });
        }

        if (newPassword !== confirmPassword) {
            return res.status(400).json({ 
                success: false, 
                message: 'Passwords do not match.' 
            });
        }

        // Validate password strength (basic validation)
        if (newPassword.length < 8) {
            return res.status(400).json({ 
                success: false, 
                message: 'Password must be at least 8 characters long.' 
            });
        }

        // Find user with valid token that hasn't expired
        const user = await User.findOne({
            resetToken: token,
            resetTokenExpiration: { $gt: Date.now() }
        });

        if (!user) {
            return res.status(400).json({ 
                success: false, 
                message: 'Invalid or expired reset token.' 
            });
        }

        // Hash the new password
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        // Update user's password and clear reset token
        user.password = hashedPassword;
        user.resetToken = undefined;
        user.resetTokenExpiration = undefined;
        await user.save();


        return res.json({ 
            success: true, 
            message: 'Password reset successful! You can now login with your new password.' 
        });

    } catch (error) {
        console.error('Password reset error:', error);
        return res.status(500).json({ 
            success: false, 
            message: 'An error occurred while resetting your password.' 
        });
    }
});

// Get all passwords for the logged-in user
app.get('/api/passwords', async (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ success: false, message: 'Not authenticated' });
    }

    try {
        const passwords = await Password.find({ userId: req.session.user.id })
            .sort({ createdAt: -1 });

        return res.json({ success: true, passwords });
    } catch (error) {
        console.error('Error fetching passwords:', error);
        return res.status(500).json({ success: false, message: 'Error fetching passwords' });
    }

});

// Add a new password
app.post('/api/passwords', async (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ success: false, message: 'Not authenticated' });
    }

    const { website, website_url, username, password, notes } = req.body;

    // Validate required fields
    if (!website || !username || !password) {
        return res.status(400).json({ 
            success: false, 
            message: 'Website, username, and password are required' 
        });
    }

    try {
        const newPassword = await Password.create({
            userId: req.session.user.id,
            website: website.trim(),
            website_url: website_url.trim(),
            username: username.trim(),
            password: password,
            notes: notes ? notes.trim() : ''
        });

        return res.json({ 
            success: true, 
            message: 'Password saved successfully',
            password: newPassword
        });
    } catch (error) {
        console.error('Error saving password:', error);
        return res.status(500).json({ success: false, message: 'Error saving password' });
    }
});

// Update an existing password
app.put('/api/passwords/:id', async (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ success: false, message: 'Not authenticated' });
    }

    const { id } = req.params;
    const { website, website_url, username, password, notes } = req.body;

    // Validate required fields
    if (!website || !username || !password) {
        return res.status(400).json({ 
            success: false, 
            message: 'Website, username, and password are required' 
        });
    }

    try {
        const updatedPassword = await Password.findOneAndUpdate(
            { _id: id, userId: req.session.user.id }, // Ensure user owns this password
            {
                website: website.trim(),
                website_url: website_url.trim(),
                username: username.trim(),
                password: password,
                notes: notes ? notes.trim() : '',
                updatedAt: Date.now()
            },
            { new: true } // Return the updated document
        );

        if (!updatedPassword) {
            return res.status(404).json({ success: false, message: 'Password not found' });
        }

        return res.json({ 
            success: true, 
            message: 'Password updated successfully',
            password: updatedPassword
        });
    } catch (error) {
        console.error('Error updating password:', error);
        return res.status(500).json({ success: false, message: 'Error updating password' });
    }
});

// Delete a password
app.delete('/api/passwords/:id', async (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ success: false, message: 'Not authenticated' });
    }

    const { id } = req.params;

    try {
        const deletedPassword = await Password.findOneAndDelete({
            _id: id,
            userId: req.session.user.id // Ensure user owns this password
        });

        if (!deletedPassword) {
            return res.status(404).json({ success: false, message: 'Password not found' });
        }

        return res.json({ 
            success: true, 
            message: 'Password deleted successfully' 
        });
    } catch (error) {
        console.error('Error deleting password:', error);
        return res.status(500).json({ success: false, message: 'Error deleting password' });
    }
});

// Search passwords by website or username
app.get('/api/passwords/search', async (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ success: false, message: 'Not authenticated' });
    }

    const { query } = req.query;

    if (!query) {
        return res.status(400).json({ success: false, message: 'Search query is required' });
    }

    try {
        const passwords = await Password.find({
            userId: req.session.user.id,
            $or: [
                { website: { $regex: query, $options: 'i' } },
                { username: { $regex: query, $options: 'i' } }
            ]
        }).sort({ createdAt: -1 });

        return res.json({ success: true, passwords });
    } catch (error) {
        console.error('Error searching passwords:', error);
        return res.status(500).json({ success: false, message: 'Error searching passwords' });
    }
});

const myserver = http.createServer(app);

myserver.listen(port, ()=>{
    console.log("server listening on port:", port);
})