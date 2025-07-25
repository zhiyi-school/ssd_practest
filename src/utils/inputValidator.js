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

        // Common SQL injection patterns
        this.sqlInjectionPatterns = [
            /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|OR|AND)\b)/gi,
            /('|(\\')|(;)|(\\;)|(\|\|)|(\/\*)|(--)|(\*\/)|(\|\|))/gi,
            /((\%27)|(\'))\s*((\%6F)|o|(\%4F))\s*((\%72)|r|(\%52))/gi,
            /((\%27)|(\'))\s*((\%55)|u|(\%75))\s*((\%4E)|n|(\%6E))\s*((\%49)|i|(\%69))\s*((\%4F)|o|(\%6F))\s*((\%4E)|n|(\%6E))/gi,
            /exec(\s|\+)+(s|x)p\w+/gi,
            /UNION\s+(ALL\s+)?SELECT/gi,
            /\b(OR|AND)\s+\d+\s*=\s*\d+/gi,
            /\b(OR|AND)\s+['"]\w+['"]\s*=\s*['"]\w+['"]|/gi,
            /\'\s*;\s*(DROP|DELETE|UPDATE|INSERT)/gi,
            /\d\s*=\s*\d\s*--/gi
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
        // Check for excessive special characters
        const specialCharCount = (input.match(/[<>'";&|(){}[\]]/g) || []).length;
        if (specialCharCount > input.length * 0.3) {
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