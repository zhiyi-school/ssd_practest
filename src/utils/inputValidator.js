class InputValidator {
    constructor() {
        // Common XSS attack patterns
        this.xssPatterns = [
            /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
            /javascript:/gi,
            /on\w+\s*=/gi,
            /<iframe/gi,
            /<object/gi,
            /<embed/gi,
            /<link/gi,
            /<meta/gi,
            /<style/gi,
            /vbscript:/gi,
            /data:text\/html/gi,
            /<img[^>]+src[^>]*=/gi,
            /expression\s*\(/gi,
            /url\s*\(/gi,
            /<[^>]*\s(on\w+|href|src)\s*=\s*['"]*javascript:/gi
        ];

        // More specific SQL injection patterns - focus on actual SQL injection syntax
        this.sqlInjectionPatterns = [
            // Classic SQL injection patterns with quotes and operators
            /('|\"|`)\s*(OR|AND)\s*('|\"|`)/gi,
            /('|\"|`)\s*(OR|AND)\s*\d+\s*=\s*\d+/gi,
            /('|\"|`)\s*(OR|AND)\s*\d+\s*<\s*\d+/gi,
            /('|\"|`)\s*(OR|AND)\s*\d+\s*>\s*\d+/gi,
            
            // UNION based attacks
            /UNION\s+(ALL\s+)?SELECT/gi,
            /\'\s*UNION/gi,
            /\"\s*UNION/gi,
            
            // Comment-based attacks
            /;\s*--/gi,
            /'\s*--/gi,
            /"\s*--/gi,
            /;\s*\/\*/gi,
            /'\s*\/\*/gi,
            /"\s*\/\*/gi,
            
            // Classic injection with quotes
            /'\s*OR\s*'.*?'\s*=\s*'/gi,
            /"\s*OR\s*".*?"\s*=\s*"/gi,
            /'\s*OR\s*1\s*=\s*1/gi,
            /"\s*OR\s*1\s*=\s*1/gi,
            
            // SQL commands with terminators
            /;\s*(DROP|DELETE|UPDATE|INSERT|CREATE|ALTER)\s/gi,
            /'\s*;\s*(DROP|DELETE|UPDATE|INSERT|CREATE|ALTER)/gi,
            /"\s*;\s*(DROP|DELETE|UPDATE|INSERT|CREATE|ALTER)/gi,
            
            // Hex encoded attacks
            /((\%27)|(\'))\s*((\%6F)|o|(\%4F))\s*((\%72)|r|(\%52))/gi,
            /((\%27)|(\'))\s*((\%55)|u|(\%75))\s*((\%4E)|n|(\%6E))\s*((\%49)|i|(\%69))\s*((\%4F)|o|(\%6F))\s*((\%4E)|n|(\%6E))/gi,
            
            // Specific dangerous patterns
            /exec(\s|\+)+(s|x)p\w+/gi,
            /sp_\w+/gi,
            /xp_\w+/gi,
            
            // Boolean-based blind SQL injection
            /\d+\s*=\s*\d+\s*--/gi,
            /\d+\s*=\s*\d+\s*#/gi,
            
            // Time-based blind SQL injection
            /WAITFOR\s+DELAY/gi,
            /SLEEP\s*\(/gi,
            /BENCHMARK\s*\(/gi,
            
            // Stacked queries
            /;\s*SELECT/gi,
            /;\s*INSERT/gi,
            /;\s*UPDATE/gi,
            /;\s*DELETE/gi
        ];
    }

    validateInput(input) {
        const errors = [];
        
        if (!input || typeof input !== 'string') {
            errors.push('Invalid input provided');
            return { isValid: false, errors, type: 'invalid' };
        }

        // Check for XSS attacks
        if (this.containsXSS(input)) {
            return { isValid: false, errors: ['Input contains potentially malicious content (XSS)'], type: 'xss' };
        }

        // Check for SQL injection
        if (this.containsSQLInjection(input)) {
            return { isValid: false, errors: ['Input contains potentially malicious content (SQL Injection)'], type: 'sqli' };
        }

        // Additional validation: length check
        if (input.length > 1000) {
            errors.push('Input is too long (maximum 1000 characters)');
        }

        // Check for suspicious character sequences
        if (this.containsSuspiciousPatterns(input)) {
            errors.push('Input contains suspicious patterns');
        }

        return {
            isValid: errors.length === 0,
            errors: errors,
            type: 'valid'
        };
    }

    containsXSS(input) {
        return this.xssPatterns.some(pattern => pattern.test(input));
    }

    containsSQLInjection(input) {
        return this.sqlInjectionPatterns.some(pattern => pattern.test(input));
    }

    containsSuspiciousPatterns(input) {
        // Check for excessive special characters that might indicate an attack
        const suspiciousChars = /[<>'";&|(){}[\]]{3,}/g;
        if (suspiciousChars.test(input)) {
            return true;
        }

        // Check for multiple SQL-like operators in sequence
        const sqlOperators = /(=|<|>|!){2,}/g;
        if (sqlOperators.test(input)) {
            return true;
        }

        // Check for encoded attacks
        if (/%[0-9a-fA-F]{2}/.test(input)) {
            try {
                const decoded = decodeURIComponent(input);
                return this.containsXSS(decoded) || this.containsSQLInjection(decoded);
            } catch (e) {
                return true; // Invalid encoding
            }
        }

        return false;
    }

    sanitizeInput(input) {
        if (!input || typeof input !== 'string') {
            return '';
        }

        // HTML encode special characters
        return input
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#x27;')
            .replace(/\//g, '&#x2F;');
    }
}

module.exports = InputValidator;