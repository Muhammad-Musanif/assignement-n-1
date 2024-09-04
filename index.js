const express = require('express');
const mongoose = require('mongoose');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const path = require('path');

const app = express();

// Connect to MongoDB
mongoose.connect("mongodb+srv://22pwbcs0927:22pwbcs0927@cluster0.ctc3n.mongodb.net/", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => {
    console.log("Database is connected");
}).catch((error) => {
    console.error("Database connection error:", error);
});

// Middleware setup
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// User Schema
const userSchema = new mongoose.Schema({
    name: String,
    email: { type: String, unique: true },
    password: String
});
const User = mongoose.model('User', userSchema);

// Middleware for authentication
const isAuthenticated = async (req, res, next) => {
    const { Token } = req.cookies;
    if (Token) {
        try {
            const decoded = jwt.verify(Token, "beproud");
            req.user = await User.findById(decoded._id);
            next();
        } catch (error) {
            res.status(401).json({ message: "Invalid token" });
        }
    } else {
        res.status(401).json({ message: "Please log in to access this resource." });
    }
};

// Routes

// Home route (Protected)
app.get('/', isAuthenticated, (req, res) => {
    res.json({ message: `Welcome, ${req.user.name}!` });
});

// Register route (renders register page)
app.get("/register", (req, res) => {
    res.sendFile(path.join(__dirname, 'register.html'));
});

// Register endpoint
app.post('/api/signup', async (req, res) => {
    const { name, email, password } = req.body;

    try {
        let user = await User.findOne({ email });
        if (user) {
            return res.status(400).json({ error: "Email already in use" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        user = await User.create({ name, email, password: hashedPassword });

        const token = jwt.sign({ _id: user._id }, "beproud", { expiresIn: '1h' });
        res.cookie("Token", token, {
            httpOnly: true,
            expires: new Date(Date.now() + 3600000), // 1 hour
        });

        res.status(201).json({ message: "User registered successfully" });
    } catch (error) {
        res.status(500).json({ error: "Internal Server Error" });
    }
});

// Login endpoint
app.post("/api/signin", async (req, res) => {
    const { email, password } = req.body;

    try {
        let user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ error: "Invalid credentials" });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ error: "Invalid credentials" });
        }

        const token = jwt.sign({ _id: user._id }, "beproud", { expiresIn: '1h' });
        res.cookie("Token", token, {
            httpOnly: true,
            expires: new Date(Date.now() + 3600000), // 1 hour
        });

        res.json({ message: "Login successful" });
    } catch (error) {
        res.status(500).json({ error: "Internal Server Error" });
    }
});

// Protected route
app.get('/api/protected', isAuthenticated, (req, res) => {
    res.json({ message: "Access granted", user: req.user });
});

// Logout endpoint
app.get('/logout', (req, res) => {
    res.cookie("Token", null, {
        httpOnly: true,
        expires: new Date(Date.now()),
    });
    res.json({ message: "Logged out successfully" });
});

// Start the server
const PORT = process.env.PORT || 5001;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}.`);
});
