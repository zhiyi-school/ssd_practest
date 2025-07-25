class InputValidator {
    constructor() {
        // Simplified XSS patterns with bounded quantifiers
        this.xssPatterns = [
            /<script\b[^<]{0,500}<\/script>/gi,
            /javascript:/gi,
            /on\w+\s{0,5}=/gi,
            /<(iframe|object|embed|link|meta|style)\b/gi,
            /vbscript:/gi,
            /data:text\/html/gi,
            /<img[^>]{0,500}src[^>]{0,200}=/gi,
            /expression\s{0,5}\(/gi,
            /<[^>]{0,200}\s(?:on\w+|href|src)\s{0,5}=\s{0,5}['"]{0,3}javascript:/gi
        ];

        // Simplified SQL injection patterns
        this.sqlInjectionPatterns = [
            /['"`]\s{0,5}(?:OR|AND)\s{0,5}['"`\d]/gi,
            /UNION\s+(?:ALL\s+)?SELECT/gi,
            /[;'"]\s{0,5}(?:--|\/\*)/gi,
            /[;'"]\s{0,5}(?:DROP|DELETE|UPDATE|INSERT|CREATE|ALTER)/gi,
            /(?:%27|')\s{0,5}(?:%6F|o)\s{0,5}(?:%72|r)/gi,
            /exec\s+[sx]p\w+/gi,
            /\d{1,10}\s{0,3}=\s{0,3}\d{1,10}\s{0,3}[--#]/gi,
            /(?:WAITFOR\s+DELAY|SLEEP\s{0,3}\(|BENCHMARK\s{0,3}\()/gi,
            /;\s{0,5}(?:SELECT|INSERT|UPDATE|DELETE)/gi
        ];

        // Configuration
        this.config = {
            maxInputLength: 10000,
            maxValidLength: 1000,
            maxExecutionTime: 30,
            maxPatternTime: 5,
            maxSuspiciousTime: 15,
            maxEncodedLength: 200,
            maxDecodedLength: 400
        };
    }

    validateInput(input) {
        if (!input || typeof input !== 'string') {
            return this.createResult(false, ['Invalid input provided'], 'invalid');
        }

        if (input.length > this.config.maxInputLength) {
            return this.createResult(false, ['Input is too long'], 'invalid');
        }

        if (this.containsAttack(input, this.xssPatterns, 'XSS')) {
            return this.createResult(false, ['Input contains potentially malicious content (XSS)'], 'xss');
        }

        if (this.containsAttack(input, this.sqlInjectionPatterns, 'SQL')) {
            return this.createResult(false, ['Input contains potentially malicious content (SQL Injection)'], 'sqli');
        }

        const errors = [];
        
        if (input.length > this.config.maxValidLength) {
            errors.push(`Input is too long (maximum ${this.config.maxValidLength} characters)`);
        }

        if (this.containsSuspiciousPatterns(input)) {
            errors.push('Input contains suspicious patterns');
        }

        return this.createResult(errors.length === 0, errors, 'valid');
    }

    containsAttack(input, patterns, type) {
        try {
            const startTime = Date.now();
            
            if (input.length > 5000) return true;
            
            for (let i = 0; i < patterns.length; i++) {
                if (this.isTimeout(startTime, this.config.maxExecutionTime)) {
                    console.warn(`${type} validation timeout exceeded`);
                    return true;
                }
                
                if (this.testPattern(patterns[i], input, type, i)) {
                    return true;
                }
            }
            
            return false;
        } catch (error) {
            console.warn(`${type} validation error:`, error.message);
            return true;
        }
    }

    testPattern(pattern, input, type, index) {
        pattern.lastIndex = 0;
        const patternStart = Date.now();
        
        try {
            const result = pattern.test(input);
            
            if (this.isTimeout(patternStart, this.config.maxPatternTime)) {
                console.warn(`${type} pattern ${index} execution time exceeded`);
                return true;
            }
            
            return result;
        } catch (regexError) {
            console.warn(`${type} regex error for pattern ${index}:`, regexError.message);
            return true;
        }
    }

    containsSuspiciousPatterns(input) {
        try {
            const startTime = Date.now();
            
            if (input.length > 2000) return true;
            
            // Check for excessive special characters
            if (this.isTimeout(startTime, this.config.maxSuspiciousTime)) return true;
            if (/[<>'";&|(){}[\]]{3,10}/.test(input)) return true;

            // Check for multiple operators
            if (this.isTimeout(startTime, this.config.maxSuspiciousTime)) return true;
            if (/[=<>!]{2,5}/.test(input)) return true;

            // Check for URL encoding
            return this.checkUrlEncoding(input);
            
        } catch (error) {
            console.warn('Suspicious pattern validation error:', error.message);
            return true;
        }
    }

    checkUrlEncoding(input) {
        if (/%[0-9a-fA-F]{2}/.test(input)) {
            try {
                if (input.length > this.config.maxEncodedLength) return true;
                
                const decoded = decodeURIComponent(input);
                
                if (decoded.length > this.config.maxDecodedLength) return true;
                
                return decoded !== input;
            } catch (e) {
                console.warn('URL decoding failed - potentially malformed input:', e.message);
                return true;
            }
        }
        return false;
    }

    sanitizeInput(input) {
        if (!input || typeof input !== 'string') {
            return '';
        }

        if (input.length > 5000) {
            input = input.substring(0, 5000);
        }

        return input
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#x27;')
            .replace(/\//g, '&#x2F;');
    }

    // Helper methods
    createResult(isValid, errors, type) {
        return { isValid, errors, type };
    }

    isTimeout(startTime, maxTime) {
        return Date.now() - startTime > maxTime;
    }
}

module.exports = InputValidator;