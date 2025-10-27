// Import necessary libraries
const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer'); // For file uploads
const path = require('path');     // For file paths
//const fs = require('fs');         // For file system operations (deleting files)

const app = express();
const port = 3000;

const JWT_SECRET = 'your-super-secret-key-that-is-long-and-random';
require('dotenv').config();

// Middleware setup
app.use(cors());
app.use(express.json());

// --- NEW: Serve static files from the 'uploads' directory ---
// This makes images accessible via URLs like http://localhost:3000/uploads/filename.jpg
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// --- Database Connection ---
// Use a connection pool for better performance and to handle multiple/concurrent requests
const fs = require('fs');

const dbConfig = {
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT || 3306,
    ssl: {
        ca: fs.readFileSync(path.join(__dirname, 'ca.pem')), // Trust Aiven CA
        rejectUnauthorized: true
    },
    connectionLimit: 10,
    waitForConnections: true,
    queueLimit: 0
};


const db = mysql.createPool(dbConfig).promise();



// --- Multer Configuration for File Uploads ---
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/'); // Save files to the 'uploads/' directory
    },
    filename: (req, file, cb) => {
        // Create a unique filename: fieldname-timestamp.extension
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({ storage: storage });

// --- Database Initialization ---
async function initializeDatabase() {
    console.log("Initializing database...");
    try {
        // The pool's `query` method handles connection acquisition and release
        await createTables();
        await seedData();
        console.log("Database initialized successfully.");
    } catch (err) {
        console.error("Error initializing database:", err);
        // Exit process if database initialization fails
        process.exit(1);
    }
}

async function createTables() {
    const usersTableQuery = `
        CREATE TABLE IF NOT EXISTS users (
            user_id INT AUTO_INCREMENT PRIMARY KEY,
            full_name VARCHAR(255) NOT NULL,
            email VARCHAR(255) NOT NULL UNIQUE,
            password_hash VARCHAR(255) NOT NULL,
            user_type ENUM('buyer', 'seller', 'agent') NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    `;
    const agentsTableQuery = `
        CREATE TABLE IF NOT EXISTS agents (
            agent_id INT AUTO_INCREMENT PRIMARY KEY,
            first_name VARCHAR(255) NOT NULL,
            last_name VARCHAR(255) NOT NULL,
            email VARCHAR(255) NOT NULL UNIQUE,
            phone VARCHAR(20),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    `;
    const propertiesTableQuery = `
        CREATE TABLE IF NOT EXISTS properties (
            property_id INT AUTO_INCREMENT PRIMARY KEY,
            agent_id INT NOT NULL,
            address VARCHAR(255) NOT NULL,
            city VARCHAR(100) NOT NULL,
            price DECIMAL(15, 2) NOT NULL,
            bedrooms INT NOT NULL,
            bathrooms DECIMAL(3, 1) NOT NULL,
            square_feet INT NOT NULL,
            description TEXT,
            status ENUM('For Sale', 'Sold', 'Pending') DEFAULT 'For Sale',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
        );
    `;

    // --- NEW: Table for multiple property images ---
    const propertyImagesTableQuery = `
        CREATE TABLE IF NOT EXISTS property_images (
            image_id INT AUTO_INCREMENT PRIMARY KEY,
            property_id INT NOT NULL,
            image_url VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (property_id) 
                REFERENCES properties(property_id) 
                ON DELETE CASCADE -- This will auto-delete images if the property is deleted
        );
    `;
    
    try {
        await db.query(usersTableQuery);
        await db.query(agentsTableQuery);
        await db.query(propertiesTableQuery);
        await db.query(propertyImagesTableQuery); // Create the new table

        // --- NEW FIX: Check and add 'created_at' column if it's missing ---
        try {
            // Test query to see if the column exists
            await db.query('SELECT created_at FROM properties LIMIT 1');
        } catch (e) {
            // If we get a "bad field" error, the column doesn't exist
            if (e.code === 'ER_BAD_FIELD_ERROR') {
                console.log("Column 'created_at' not found in 'properties' table. Adding it...");
                // Add the column
                await db.query('ALTER TABLE properties ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP');
                console.log("Column 'created_at' added successfully.");
            } else {
                throw e; // Re-throw any other errors
            }
        }
        // --- END FIX ---

        console.log("All database tables checked/created successfully.");
    } catch (err) {
        console.error("Error creating tables:", err);
        throw err; // Re-throw error to be caught by initializeDatabase
    }
}

async function seedData() {
    try {
        // Seed Agents
        const [agentRows] = await db.query('SELECT COUNT(*) as count FROM agents');
        if (agentRows[0].count === 0) {
            await db.query(`
                INSERT INTO agents (first_name, last_name, email, phone) VALUES
                ('Jane', 'Doe', 'jane.doe@dreamhome.com', '123-456-7890'),
                ('John', 'Smith', 'john.smith@dreamhome.com', '098-765-4321');
            `);
            console.log("Agents seeded.");
        }

        // Seed Users (for login)
        const [userRows] = await db.query('SELECT COUNT(*) as count FROM users');
        if (userRows[0].count === 0) {
            const buyerHash = await bcrypt.hash('password123', 10);
            const sellerHash = await bcrypt.hash('password123', 10);
            
            await db.query(`
                INSERT INTO users (full_name, email, password_hash, user_type) VALUES
                ('Test Buyer', 'buyer@test.com', ?, 'buyer'),
                ('Test Seller', 'seller@test.com', ?, 'seller');
            `, [buyerHash, sellerHash]);
            console.log("Test users seeded.");
        }
    } catch (err) {
        console.error("Error seeding data:", err);
        throw err;
    }
}

// --- Authentication Middleware ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Format is "Bearer TOKEN"
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};


// --- API Endpoints ---

// --- MODIFIED: GET Endpoint to fetch all properties (with multiple images) ---
app.get('/api/properties', async (req, res) => {
    try {
        // This query joins properties, agents, and groups all images for each property
        // into a single comma-separated string using GROUP_CONCAT.
        // --- FIX: Changed JOIN to LEFT JOIN and added COALESCE for resilience ---
        const query = `
            SELECT 
                p.*, 
                COALESCE(a.first_name, 'N/A') AS first_name, 
                COALESCE(a.last_name, '') AS last_name, 
                COALESCE(a.email, 'No agent listed') AS agent_email,
                GROUP_CONCAT(pi.image_url) AS images
            FROM properties p
            LEFT JOIN agents a ON p.agent_id = a.agent_id
            LEFT JOIN property_images pi ON p.property_id = pi.property_id
            GROUP BY p.property_id
            ORDER BY p.created_at DESC;
        `;
        const [rows] = await db.query(query);
        res.json(rows);
    } catch (err) {
        console.error("Database query failed:", err);
        res.status(500).send("Error fetching properties from the database.");
    }
});

// --- MODIFIED: POST Endpoint to create a new property (with multiple images) ---
// Use `upload.array('propertyImages', 10)` to accept up to 10 files
app.post('/api/properties', authenticateToken, upload.array('propertyImages', 10), async (req, res) => {
    
    // Check user role
    if (req.user.userType !== 'seller') {
        return res.status(403).json({ message: 'Access denied. Only sellers can list properties.' });
    }

    // Check if files were uploaded
    if (!req.files || req.files.length === 0) {
        return res.status(400).json({ message: 'Please upload at least one property image.' });
    }
    
    const { address, city, price, bedrooms, bathrooms, square_feet, description } = req.body;
    
    // Basic validation
    if (!address || !city || !price || !bedrooms || !bathrooms || !square_feet || !description) {
        return res.status(400).json({ message: "Please provide all property details." });
    }

    // Get a connection from the pool for the transaction
    let connection;
    try {
        connection = await db.getConnection();
        await connection.beginTransaction(); // Start transaction

        // 1. Insert the property
        const propertyQuery = `
            INSERT INTO properties (agent_id, address, city, price, bedrooms, bathrooms, square_feet, description, status) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'For Sale')
        `;
        // Randomly assign agent 1 or 2
        const agentId = Math.ceil(Math.random() * 2); 
        
        const [insertResult] = await connection.query(propertyQuery, [
            agentId, address, city, price, bedrooms, bathrooms, square_feet, description
        ]);
        
        const newPropertyId = insertResult.insertId;

        // 2. Prepare and insert all images
        const imagesQuery = `
            INSERT INTO property_images (property_id, image_url) VALUES ?
        `;
        // 'req.files' is an array of uploaded file objects
        // 'file.path' is the path saved by multer (e.g., "uploads/filename.jpg")
        const imagePaths = req.files.map(file => [newPropertyId, file.path]);
        
        await connection.query(imagesQuery, [imagePaths]);

        // 3. If all good, commit the transaction
        await connection.commit();

        res.status(201).json({ message: 'Property listed successfully!' });

    } catch (err) {
        // 4. If error, rollback the transaction
        if (connection) await connection.rollback(); 
        
        // Also, delete any files that were uploaded for this failed request
        if (req.files) {
            req.files.forEach(file => {
                fs.unlink(file.path, (unlinkErr) => {
                    if (unlinkErr) console.error(`Failed to delete uploaded file on error: ${file.path}`, unlinkErr);
                });
            });
        }
        
        console.error("Failed to list property (transaction rolled back):", err);
        // --- FIX: Changed 5.00 to 500 ---
        res.status(500).json({ message: "An error occurred while listing the property." });
    } finally {
        // 5. Always release the connection back to the pool
        if (connection) connection.release();
    }
});


// POST Endpoint for User Registration
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password, userType } = req.body;
        if (!name || !email || !password || !userType) {
            return res.status(400).json({ message: "Please provide all required fields." });
        }
        const [existingUsers] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
        if (existingUsers.length > 0) {
            return res.status(409).json({ message: "An account with this email already exists." });
        }
        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(password, salt);
        const query = 'INSERT INTO users (full_name, email, password_hash, user_type) VALUES (?, ?, ?, ?)';
        await db.query(query, [name, email, passwordHash, userType]);
        res.status(201).json({ message: "User registered successfully!" });
    } catch (err) {
        console.error("Registration failed:", err);
        res.status(500).json({ message: "An error occurred during registration." });
    }
});

// POST Endpoint for User Login
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ message: "Please provide email and password." });
        }
        const [users] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
        const user = users[0];
        if (!user) {
            // --- FIX: Changed 4G01 to 401 ---
            return res.status(401).json({ message: "Invalid credentials." });
        }
        const isPasswordMatch = await bcrypt.compare(password, user.password_hash);
        if (!isPasswordMatch) {
            return res.status(401).json({ message: "Invalid credentials." });
        }
        const token = jwt.sign(
            { userId: user.user_id, email: user.email, userType: user.user_type },
            JWT_SECRET,
            { expiresIn: '1h' }
        );
        res.json({
            message: "Login successful!",
            token: token,
            user: {
                id: user.user_id,
                name: user.full_name,
                role: user.user_type
            }
        });
    } catch (err) {
        console.error("Login failed:", err);
        res.status(500).json({ message: "An error occurred during login." });
    }
});


// PUT Endpoint to update property status (protected)
app.put('/api/properties/:id/status', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { newStatus } = req.body;

    if (!['For Sale', 'Sold', 'Pending'].includes(newStatus)) {
        return res.status(400).json({ message: "Invalid property status." });
    }

    try {
        const query = 'UPDATE properties SET status = ? WHERE property_id = ?';
        await db.query(query, [newStatus, id]);
        res.json({ message: `Property ${id} status updated to ${newStatus}.` });
    } catch (err) {
        console.error("Failed to update property status:", err);
        res.status(500).json({ message: "An error occurred while updating the status." });
    }
});

// --- MODIFIED: DELETE Endpoint to remove a property (protected) ---
app.delete('/api/properties/:id', authenticateToken, async (req, res) => {
    const propertyId = req.params.id;

    try {
        // 1. Find all images associated with this property
        const [images] = await db.query('SELECT image_url FROM property_images WHERE property_id = ?', [propertyId]);
        
        // 2. Delete the actual files from the 'uploads/' folder
        for (const img of images) {
            // path.join safely creates the full path to the file
            const filePath = path.join(__dirname, img.image_url);
            
            // fs.unlink deletes the file. We wrap in a try/catch in case one file
            // fails, we still want to continue.
            try {
                if (fs.existsSync(filePath)) { // Check if file exists before trying to delete
                    fs.unlinkSync(filePath);
                    console.log(`Deleted file: ${filePath}`);
                }
            } catch (unlinkErr) {
                console.error(`Failed to delete file ${filePath}:`, unlinkErr);
            }
        }

        // 3. Delete the property record from the 'properties' table.
        //    The 'ON DELETE CASCADE' in the 'property_images' table
        //    will automatically delete all its image records from the DB.
        await db.query('DELETE FROM properties WHERE property_id = ?', [propertyId]);

        res.json({ message: `Property ${propertyId} and all associated images have been deleted.` });

    } catch (err) {
        console.error(`Failed to delete property ${propertyId}:`, err);
        res.status(500).json({ message: "An error occurred while deleting the property." });
    }
});


// --- Server Start ---
// Ensure database is ready before starting the server
initializeDatabase().then(() => {
    app.listen(port, () => {
        console.log(`Server is running at http://localhost:${port}`);
    });
}).catch(err => {
    console.error("Failed to start server:", err);
});



