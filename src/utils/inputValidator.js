class InputValidator {
    constructor() {
        // Common XSS attack patterns - fixed for ReDoS prevention
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
            /<[^>]*\s(?:on\w+|href|src)\s*=\s*['"]*javascript:/gi
        ];

        // Fixed SQL injection patterns - preventing ReDoS by limiting quantifiers
        this.sqlInjectionPatterns = [
            // Classic SQL injection patterns with quotes and operators - limited quantifiers
            /['"`]\s{0,5}(?:OR|AND)\s{0,5}['"`]/gi,
            /['"`]\s{0,5}(?:OR|AND)\s{0,5}\d+\s{0,5}=\s{0,5}\d+/gi,
            /['"`]\s{0,5}(?:OR|AND)\s{0,5}\d+\s{0,5}<\s{0,5}\d+/gi,
            /['"`]\s{0,5}(?:OR|AND)\s{0,5}\d+\s{0,5}>\s{0,5}\d+/gi,
            
            // UNION based attacks
            /UNION\s+(?:ALL\s+)?SELECT/gi,
            /'\s{0,5}UNION/gi,
            /"\s{0,5}UNION/gi,
            
            // Comment-based attacks - limited whitespace
            /;\s{0,5}--/gi,
            /'\s{0,5}--/gi,
            /"\s{0,5}--/gi,
            /;\s{0,5}\/\*/gi,
            /'\s{0,5}\/\*/gi,
            /"\s{0,5}\/\*/gi,
            
            // Classic injection with quotes - limited quantifiers
            /'\s{0,5}OR\s{0,5}'[^']{0,100}'\s{0,5}=\s{0,5}'/gi,
            /"\s{0,5}OR\s{0,5}"[^"]{0,100}"\s{0,5}=\s{0,5}"/gi,
            /'\s{0,5}OR\s{0,5}1\s{0,5}=\s{0,5}1/gi,
            /"\s{0,5}OR\s{0,5}1\s{0,5}=\s{0,5}1/gi,
            
            // SQL commands with terminators - limited whitespace
            /;\s{0,5}(?:DROP|DELETE|UPDATE|INSERT|CREATE|ALTER)\s/gi,
            /'\s{0,5};\s{0,5}(?:DROP|DELETE|UPDATE|INSERT|CREATE|ALTER)/gi,
            /"\s{0,5};\s{0,5}(?:DROP|DELETE|UPDATE|INSERT|CREATE|ALTER)/gi,
            
            // Hex encoded attacks - simplified patterns
            /(?:%27|')\s{0,5}(?:%6F|o)\s{0,5}(?:%72|r)/gi,
            /(?:%27|')\s{0,5}(?:%55|u)\s{0,5}(?:%4E|n)\s{0,5}(?:%49|i)\s{0,5}(?:%4F|o)\s{0,5}(?:%4E|n)/gi,
            
            // Specific dangerous patterns
            /exec\s+(?:s|x)p\w+/gi,
            /sp_\w+/gi,
            /xp_\w+/gi,
            
            // Boolean-based blind SQL injection - FIXED: limited quantifiers instead of \s*
            /\d+\s{0,3}=\s{0,3}\d+\s{0,3}--/gi,
            /\d+\s{0,3}=\s{0,3}\d+\s{0,3}#/gi,
            
            // Time-based blind SQL injection
            /WAITFOR\s+DELAY/gi,
            /SLEEP\s{0,3}\(/gi,
            /BENCHMARK\s{0,3}\(/gi,
            
            // Stacked queries - limited whitespace
            /;\s{0,5}SELECT/gi,
            /;\s{0,5}INSERT/gi,
            /;\s{0,5}UPDATE/gi,
            /;\s{0,5}DELETE/gi
        ];
    }

    validateInput(input) {
        const errors = [];
        
        if (!input || typeof input !== 'string') {
            errors.push('Invalid input provided');
            return { isValid: false, errors, type: 'invalid' };
        }

        // Prevent processing of extremely long inputs to avoid ReDoS
        if (input.length > 10000) {
            return { isValid: false, errors: ['Input is too long'], type: 'invalid' };
        }

        // Check for XSS attacks with timeout
        if (this.containsXSS(input)) {
            return { isValid: false, errors: ['Input contains potentially malicious content (XSS)'], type: 'xss' };
        }

        // Check for SQL injection with timeout
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
        // Add timeout protection for regex execution
        try {
            const startTime = Date.now();
            return this.xssPatterns.some(pattern => {
                // Prevent long-running regex
                if (Date.now() - startTime > 100) {
                    throw new Error('Regex timeout');
                }
                // Reset regex lastIndex to prevent issues with global flags
                pattern.lastIndex = 0;
                return pattern.test(input);
            });
        } catch (error) {
            // If regex fails or times out, consider it suspicious
            return true;
        }
    }

    containsSQLInjection(input) {
        // Add timeout protection for regex execution
        try {
            const startTime = Date.now();
            return this.sqlInjectionPatterns.some(pattern => {
                // Prevent long-running regex
                if (Date.now() - startTime > 100) {
                    throw new Error('Regex timeout');
                }
                // Reset regex lastIndex to prevent issues with global flags
                pattern.lastIndex = 0;
                return pattern.test(input);
            });
        } catch (error) {
            // If regex fails or times out, consider it suspicious
            return true;
        }
    }

    containsSuspiciousPatterns(input) {
        try {
            const startTime = Date.now();
            
            // Check for excessive special characters - fixed pattern with limited quantifier
            const suspiciousChars = /[<>'";&|(){}[\]]{3,10}/g;
            if (suspiciousChars.test(input)) {
                return true;
            }

            // Prevent timeout
            if (Date.now() - startTime > 50) {
                return true;
            }

            // Check for multiple SQL-like operators in sequence - limited quantifier
            const sqlOperators = /[=<>!]{2,5}/g;
            if (sqlOperators.test(input)) {
                return true;
            }

            // Check for encoded attacks with length limit
            if (/%[0-9a-fA-F]{2}/.test(input)) {
                try {
                    // Limit decoded length to prevent ReDoS
                    if (input.length > 1000) {
                        return true;
                    }
                    const decoded = decodeURIComponent(input);
                    if (decoded.length > 2000) {
                        return true;
                    }
                    return this.containsXSS(decoded) || this.containsSQLInjection(decoded);
                } catch (e) {
                    return true; // Invalid encoding
                }
            }

            return false;
        } catch (error) {
            // If pattern matching fails, consider it suspicious
            return true;
        }
    }

    sanitizeInput(input) {
        if (!input || typeof input !== 'string') {
            return '';
        }

        // Limit input length before sanitization
        if (input.length > 10000) {
            input = input.substring(0, 10000);
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