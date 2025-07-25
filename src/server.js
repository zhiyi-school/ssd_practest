const express = require('express');
const path = require('path');
const InputValidator = require('./utils/inputValidator');

const app = express();

app.disable('x-powered-by');
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';");
    next();
});

const inputValidator = new InputValidator();

// Serve static files from public directory
app.use(express.static(path.join(__dirname, 'public')));

// Parse form data
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Home route
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Results page route
app.get('/results', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'results.html'));
});

// Search route with input validation
app.post('/search', (req, res) => {
    const { searchTerm } = req.body;
    
    if (!searchTerm) {
        return res.json({ success: false, errors: ['Search term is required'] });
    }

    const validation = inputValidator.validateInput(searchTerm);
    
    if (validation.isValid) {
        // Input is safe, sanitize and return success
        const sanitizedTerm = inputValidator.sanitizeInput(searchTerm);
        res.json({ 
            success: true, 
            message: 'Search term is valid',
            sanitizedTerm: sanitizedTerm
        });
    } else {
        // Input contains malicious content, return error
        let errorMessage = validation.errors;
        
        // Add specific messages based on attack type
        if (validation.type === 'xss') {
            errorMessage.push('Input cleared due to potential XSS attack');
        } else if (validation.type === 'sqli') {
            errorMessage.push('Input cleared due to potential SQL injection attack');
        }
        
        res.json({ 
            success: false, 
            errors: errorMessage,
            type: validation.type
        });
    }
});

const PORT = process.env.PORT || 80;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});