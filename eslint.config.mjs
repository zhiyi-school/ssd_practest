import globals from "globals";
import pluginJs from "@eslint/js";
import pluginReact from "eslint-plugin-react";
import pluginSecurity from "eslint-plugin-security";
import tseslint from "@typescript-eslint/eslint-plugin";
import tsparser from "@typescript-eslint/parser";

/** @type {import('eslint').Linter.Config[]} */
export default [
  {
    files: ["**/*.{js,mjs,cjs,jsx,ts,tsx}"],
    languageOptions: { 
      globals: {
        ...globals.browser,
        ...globals.node
      }
    }
  },
  // ESLint recommended rules
  pluginJs.configs.recommended,
  
  // React recommended rules
  {
    files: ["**/*.{jsx,tsx}"],
    plugins: {
      react: pluginReact
    },
    rules: {
      ...pluginReact.configs.recommended.rules,
    },
    settings: {
      react: {
        version: "detect"
      }
    }
  },
  
  // TypeScript recommended rules
  {
    files: ["**/*.{ts,tsx}"],
    languageOptions: {
      parser: tsparser,
      parserOptions: {
        ecmaVersion: "latest",
        sourceType: "module"
      }
    },
    plugins: {
      "@typescript-eslint": tseslint
    },
    rules: {
      ...tseslint.configs.recommended.rules,
    }
  },
  
  // Security recommended rules
  {
    plugins: {
      security: pluginSecurity
    },
    rules: {
      ...pluginSecurity.configs.recommended.rules,
      "security/detect-eval-with-expression": "error",
      "security/detect-object-injection": "error",
      "security/detect-non-literal-fs-filename": "warn",
      "security/detect-unsafe-regex": "error",
      "security/detect-buffer-noassert": "error",
      "security/detect-child-process": "error",
      "security/detect-disable-mustache-escape": "error",
      "security/detect-no-csrf-before-method-override": "error",
      "security/detect-non-literal-regexp": "error",
      "security/detect-possible-timing-attacks": "warn",
      "security/detect-pseudoRandomBytes": "error"
    }
  },
  
  // Browser-specific config
  {
    files: ["src/public/**/*.js"],
    languageOptions: { 
      globals: globals.browser 
    }
  },
  
  // Node.js-specific config  
  {
    files: ["src/server.js", "src/utils/**/*.js"],
    languageOptions: { 
      globals: globals.node 
    }
  }
];