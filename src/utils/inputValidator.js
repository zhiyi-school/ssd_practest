class InputValidator {
    constructor() {
        // Common XSS attack patterns - COMPLETELY FIXED for ReDoS prevention
        this.xssPatterns = [
            // FIXED: Replaced complex nested quantifiers with bounded alternatives
            /<script\b[^<]{0,500}(?:(?!<\/script>)[^<]){0,200}<\/script>/gi,
            /javascript:/gi,
            /on\w+\s{0,5}=/gi,
            /<iframe/gi,
            /<object/gi,
            /<embed/gi,
            /<link/gi,
            /<meta/gi,
            /<style/gi,
            /vbscript:/gi,
            /data:text\/html/gi,
            /<img[^>]{0,500}src[^>]{0,200}=/gi,
            /expression\s{0,5}\(/gi,
            /url\s{0,5}\(/gi,
            /<[^>]{0,200}\s(?:on\w+|href|src)\s{0,5}=\s{0,5}['"]{0,3}javascript:/gi
        ];

        // SQL injection patterns - ALL SAFE from ReDoS
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
            
            // Boolean-based blind SQL injection - COMPLETELY SAFE: bounded quantifiers
            /\d{1,10}\s{0,3}=\s{0,3}\d{1,10}\s{0,3}--/gi,
            /\d{1,10}\s{0,3}=\s{0,3}\d{1,10}\s{0,3}#/gi,
            
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

        // Check for XSS attacks with enhanced timeout protection
        if (this.containsXSS(input)) {
            return { isValid: false, errors: ['Input contains potentially malicious content (XSS)'], type: 'xss' };
        }

        // Check for SQL injection with enhanced timeout protection
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
        // Circuit breaker pattern with strict timeout controls
        try {
            const startTime = Date.now();
            const maxExecutionTime = 30; // Reduced for safety
            
            // Early termination for extremely long inputs
            if (input.length > 5000) {
                return true;
            }
            
            for (let i = 0; i < this.xssPatterns.length; i++) {
                // Global timeout check
                if (Date.now() - startTime > maxExecutionTime) {
                    console.warn('XSS validation timeout exceeded');
                    return true; // Fail-safe: assume malicious
                }
                
                const pattern = this.xssPatterns[i];
                pattern.lastIndex = 0; // Reset for global regex
                
                // Individual pattern timeout protection
                const patternStart = Date.now();
                try {
                    const result = pattern.test(input);
                    
                    // Check individual pattern execution time
                    if (Date.now() - patternStart > 5) {
                        console.warn(`XSS pattern ${i} execution time exceeded`);
                        return true; // Fail-safe
                    }
                    
                    if (result) {
                        return true;
                    }
                } catch (regexError) {
                    console.warn(`XSS regex error for pattern ${i}:`, regexError.message);
                    return true; // Fail-safe
                }
            }
            return false;
        } catch (error) {
            console.warn('XSS validation error:', error.message);
            return true; // Fail-safe
        }
    }

    containsSQLInjection(input) {
        // Circuit breaker pattern with strict timeout controls
        try {
            const startTime = Date.now();
            const maxExecutionTime = 30; // Reduced for safety
            
            // Early termination for extremely long inputs
            if (input.length > 5000) {
                return true;
            }
            
            for (let i = 0; i < this.sqlInjectionPatterns.length; i++) {
                // Global timeout check
                if (Date.now() - startTime > maxExecutionTime) {
                    console.warn('SQL injection validation timeout exceeded');
                    return true; // Fail-safe: assume malicious
                }
                
                const pattern = this.sqlInjectionPatterns[i];
                pattern.lastIndex = 0; // Reset for global regex
                
                // Individual pattern timeout protection
                const patternStart = Date.now();
                try {
                    const result = pattern.test(input);
                    
                    // Check individual pattern execution time
                    if (Date.now() - patternStart > 5) {
                        console.warn(`SQL injection pattern ${i} execution time exceeded`);
                        return true; // Fail-safe
                    }
                    
                    if (result) {
                        return true;
                    }
                } catch (regexError) {
                    console.warn(`SQL injection regex error for pattern ${i}:`, regexError.message);
                    return true; // Fail-safe
                }
            }
            return false;
        } catch (error) {
            console.warn('SQL injection validation error:', error.message);
            return true; // Fail-safe
        }
    }

    containsSuspiciousPatterns(input) {
        try {
            const startTime = Date.now();
            const maxExecutionTime = 15; // Very short timeout
            
            // Early exit for long inputs
            if (input.length > 2000) {
                return true;
            }
            
            // Check for excessive special characters - completely safe pattern
            const suspiciousChars = /[<>'";&|(){}[\]]{3,10}/;
            if (Date.now() - startTime > maxExecutionTime) return true;
            if (suspiciousChars.test(input)) {
                return true;
            }

            // Check for multiple SQL-like operators - completely safe pattern
            const sqlOperators = /[=<>!]{2,5}/;
            if (Date.now() - startTime > maxExecutionTime) return true;
            if (sqlOperators.test(input)) {
                return true;
            }

            // Check for encoded attacks with very strict limits
            if (/%[0-9a-fA-F]{2}/.test(input)) {
                try {
                    // Extremely restrictive limits
                    if (input.length > 200) {
                        return true;
                    }
                    const decoded = decodeURIComponent(input);
                    if (decoded.length > 400) {
                        return true;
                    }
                    // No recursive calls to prevent ReDoS
                    return decoded !== input; // Simple check for encoding
                } catch (e) {
                    return true; // Invalid encoding
                }
            }

            return false;
        } catch (error) {
            console.warn('Suspicious pattern validation error:', error.message);
            return true; // Fail-safe
        }
    }

    sanitizeInput(input) {
        if (!input || typeof input !== 'string') {
            return '';
        }

        // Strict input length limits
        if (input.length > 5000) {
            input = input.substring(0, 5000);
        }

        // HTML encode special characters (safe operations)
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