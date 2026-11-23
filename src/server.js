const express = require('express');
const cors = require('cors');
const path = require('path');

const noEncryptionRoutes = require('./routes/noEncryptionRoutes');
const aesRoutes = require('./routes/aesRoutes');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Static files
app.use(express.static(path.join(__dirname, '..', 'public')));

// Health check
app.get('/api/health', (req, res) => {
    res.json({
        status: 'ok',
        message: 'Server berjalan dengan baik',
        timestamp: new Date().toISOString()
    });
});

// No Encryption routes
app.use('/api/no-encryption', noEncryptionRoutes);

// AES routes
app.use('/api/aes', aesRoutes);

// Start server
app.listen(PORT, '0.0.0.0', () => {
    console.log('===================================');
    console.log(' Secure Communication Research Lab ');
    console.log('===================================');
    console.log(`Server berjalan pada port ${PORT}`);
    console.log(`Local URL : http://localhost:${PORT}`);

    const os = require('os');
    const interfaces = os.networkInterfaces();

    for (const [name, addresses] of Object.entries(interfaces)) {
        for (const address of addresses || []) {
            if (address.family === 'IPv4' && !address.internal) {
                console.log(
                    `${name}: http://${address.address}:${PORT}`
                );
            }
        }
    }
});