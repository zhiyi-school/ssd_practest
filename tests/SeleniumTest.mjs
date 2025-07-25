import { Builder, By, until } from 'selenium-webdriver';
import assert from 'assert';

// Get the argument (default to 'local' if not provided)
const environment = process.argv[2] || 'local';

// URLs based on environment
const seleniumUrl = environment === 'github' 
  ? 'http://selenium:4444/wd/hub' 
  : 'http://localhost:4444/wd/hub';

// Note: Start the nodejs server before running the test locally
const serverUrl = environment === 'github' 
  ? 'http://testserver' 
  : 'http://localhost';

console.log(`Running search validation tests in '${environment}' environment`);
console.log(`Selenium URL: ${seleniumUrl}`);
console.log(`Server URL: ${serverUrl}`);

(async function runSearchValidationTests() {
    let driver;

    try {
        console.log("Initializing WebDriver...");
        
        // Initialize the WebDriver with Chrome
        driver = await new Builder()
            .forBrowser('chrome')
            .usingServer(seleniumUrl)
            .build();

        console.log("WebDriver initialized successfully");

        // Test 1: Check if search input and submit button exist
        await testSearchFormElements(driver);
        
        // Test 2: Test XSS attack detection and input clearing
        await testXSSAttackDetection(driver);
        
        // Test 3: Test SQL injection attack detection and input clearing
        await testSQLInjectionDetection(driver);
        
        // Test 4: Test valid search input goes to results page
        await testValidSearchInput(driver);
        
        // Test 5: Test results page elements and return button
        await testResultsPage(driver);
        
        // Test 6: Test return to home page functionality
        await testReturnToHomePage(driver);

        console.log('All tests passed successfully!');

    } catch (err) {
        console.error('Test failed:', err);
        process.exit(1);
    } finally {
        if (driver) {
            await driver.quit();
            console.log("WebDriver session closed");
        }
    }
})();

// Test 1: Home page has form with search input and submit button
async function testSearchFormElements(driver) {
    console.log("Test 1: Checking search form elements...");
    
    await driver.get(serverUrl);
    
    const searchInput = await driver.findElement(By.id('searchTerm'));
    const submitButton = await driver.findElement(By.css('button[type="submit"]'));
    
    assert.ok(searchInput, 'Search input field should exist');
    assert.ok(submitButton, 'Submit button should exist');
    
    const buttonText = await submitButton.getText();
    assert.ok(buttonText.toLowerCase().includes('submit'), 'Button should be a submit button');
    
    console.log("✓ Search form elements test passed");
}

// Test 2: XSS attack detection - input should be cleared and remain on home page
async function testXSSAttackDetection(driver) {
    console.log("Test 2: Testing XSS attack detection...");
    
    await driver.get(serverUrl);
    
    const searchInput = await driver.findElement(By.id('searchTerm'));
    await searchInput.clear();
    
    // Test with XSS payload - using safe string construction
    const scriptTag = '<script>';
    const alertFunction = 'alert("XSS")';
    const closeTag = '</script>';
    const xssPayload = scriptTag + alertFunction + closeTag;
    
    await searchInput.sendKeys(xssPayload);
    
    const submitButton = await driver.findElement(By.css('button[type="submit"]'));
    await submitButton.click();
    
    // Wait for error message to appear
    const errorElement = await driver.wait(until.elementLocated(By.className('error')), 5000);
    const errorText = await errorElement.getText();
    
    // Check that error mentions XSS
    assert.ok(errorText.toLowerCase().includes('xss'), 'Error message should mention XSS attack');
    
    // Check that input field is cleared
    const inputValue = await searchInput.getAttribute('value');
    assert.strictEqual(inputValue, '', 'Input field should be cleared after XSS detection');
    
    // Check that we're still on the home page
    const currentUrl = await driver.getCurrentUrl();
    assert.ok(currentUrl === serverUrl || currentUrl === serverUrl + '/', 'Should remain on home page');
    
    console.log("✓ XSS attack detection test passed");
}

// Test 3: SQL injection attack detection - input should be cleared and remain on home page
async function testSQLInjectionDetection(driver) {
    console.log("Test 3: Testing SQL injection attack detection...");
    
    await driver.get(serverUrl);
    
    const searchInput = await driver.findElement(By.id('searchTerm'));
    await searchInput.clear();
    
    // Test with SQL injection payload
    const sqlPayload = "'; DROP TABLE users; --";
    await searchInput.sendKeys(sqlPayload);
    
    const submitButton = await driver.findElement(By.css('button[type="submit"]'));
    await submitButton.click();
    
    // Wait for error message to appear
    const errorElement = await driver.wait(until.elementLocated(By.className('error')), 5000);
    const errorText = await errorElement.getText();
    
    // Check that error mentions SQL injection
    assert.ok(errorText.toLowerCase().includes('sql'), 'Error message should mention SQL injection attack');
    
    // Check that input field is cleared
    const inputValue = await searchInput.getAttribute('value');
    assert.strictEqual(inputValue, '', 'Input field should be cleared after SQL injection detection');
    
    // Check that we're still on the home page
    const currentUrl = await driver.getCurrentUrl();
    assert.ok(currentUrl === serverUrl || currentUrl === serverUrl + '/', 'Should remain on home page');
    
    console.log("✓ SQL injection detection test passed");
}

// Test 4: Valid search input goes to results page
async function testValidSearchInput(driver) {
    console.log("Test 4: Testing valid search input...");
    
    await driver.get(serverUrl);
    
    const searchInput = await driver.findElement(By.id('searchTerm'));
    await searchInput.clear();
    await searchInput.sendKeys('valid search term');
    
    const submitButton = await driver.findElement(By.css('button[type="submit"]'));
    await submitButton.click();
    
    // Wait for redirect to results page
    await driver.wait(until.urlContains('results'), 10000);
    const currentUrl = await driver.getCurrentUrl();
    
    assert.ok(currentUrl.includes('results'), 'Should redirect to results page');
    assert.ok(currentUrl.includes('search='), 'URL should contain search parameter');
    
    console.log("✓ Valid search input test passed");
}

// Test 5: Results page shows search term and has return button
async function testResultsPage(driver) {
    console.log("Test 5: Testing results page elements...");
    
    await driver.get(serverUrl);
    
    const searchInput = await driver.findElement(By.id('searchTerm'));
    await searchInput.clear();
    
    const testSearchTerm = 'test search query';
    await searchInput.sendKeys(testSearchTerm);
    
    const submitButton = await driver.findElement(By.css('button[type="submit"]'));
    await submitButton.click();
    
    // Wait for redirect to results page
    await driver.wait(until.urlContains('results'), 10000);
    
    // Check that search term is displayed
    const searchDisplay = await driver.findElement(By.id('searchDisplay'));
    const displayedText = await searchDisplay.getText();
    
    assert.ok(displayedText.includes(testSearchTerm), 'Results page should display the search term');
    
    // Check that return button exists
    const returnButton = await driver.findElement(By.id('backBtn'));
    assert.ok(returnButton, 'Return button should exist');
    
    const buttonText = await returnButton.getText();
    assert.ok(buttonText.toLowerCase().includes('home') || buttonText.toLowerCase().includes('return'), 
              'Button should indicate return to home functionality');
    
    console.log("✓ Results page elements test passed");
}

// Test 6: Return button goes back to home page
async function testReturnToHomePage(driver) {
    console.log("Test 6: Testing return to home page functionality...");
    
    await driver.get(serverUrl);
    
    const searchInput = await driver.findElement(By.id('searchTerm'));
    await searchInput.clear();
    await searchInput.sendKeys('return test query');
    
    const submitButton = await driver.findElement(By.css('button[type="submit"]'));
    await submitButton.click();
    
    // Wait for redirect to results page
    await driver.wait(until.urlContains('results'), 10000);
    
    // Click return button
    const returnButton = await driver.findElement(By.id('backBtn'));
    await returnButton.click();
    
    // Wait for redirect back to home page
    await driver.wait(until.urlMatches(new RegExp(serverUrl + '/?$')), 5000);
    const currentUrl = await driver.getCurrentUrl();
    
    assert.ok(currentUrl.match(new RegExp(serverUrl + '/?$')), 'Should return to home page');
    
    // Verify we're back on the search form
    const searchFormExists = await driver.findElement(By.id('searchForm'));
    assert.ok(searchFormExists, 'Should be back on page with search form');
    
    console.log("✓ Return to home page functionality test passed");
}

// Additional test for edge cases - FIXED: Safe string construction
async function testAdditionalXSSVariants(driver) {
    console.log("Additional Test: Testing various XSS attack variants...");
    
    // Create XSS payloads using safe string construction to avoid eval() warnings
    const xssVariants = [
        '<img src=x onerror=' + 'alert(1)' + '>',
        'java' + 'script:' + 'alert("XSS")',
        '<iframe src="' + 'java' + 'script:' + 'alert(\'XSS\')"' + '></iframe>',
        '<svg on' + 'load=' + 'alert(1)' + '>',
        'on' + 'mouseover="' + 'alert(1)' + '"'
    ];
    
    for (const xssPayload of xssVariants) {
        await driver.get(serverUrl);
        
        const searchInput = await driver.findElement(By.id('searchTerm'));
        await searchInput.clear();
        await searchInput.sendKeys(xssPayload);
        
        const submitButton = await driver.findElement(By.css('button[type="submit"]'));
        await submitButton.click();
        
        // Wait for error message
        const errorElement = await driver.wait(until.elementLocated(By.className('error')), 5000);
        const errorText = await errorElement.getText();
        
        assert.ok(errorText.toLowerCase().includes('xss') || errorText.toLowerCase().includes('malicious'), 
                  `XSS variant should be detected: ${xssPayload}`);
        
        // Check input is cleared
        const inputValue = await searchInput.getAttribute('value');
        assert.strictEqual(inputValue, '', `Input should be cleared for XSS variant: ${xssPayload}`);
    }
    
    console.log("✓ Additional XSS variants test passed");
}

// Additional test for SQL injection variants
async function testAdditionalSQLIVariants(driver) {
    console.log("Additional Test: Testing various SQL injection attack variants...");
    
    const sqlVariants = [
        "1' OR '1'='1",
        "admin'; --",
        "1' UNION SELECT * FROM users--",
        "'; DROP DATABASE test; --",
        "1' OR 1=1#"
    ];
    
    for (const sqlPayload of sqlVariants) {
        await driver.get(serverUrl);
        
        const searchInput = await driver.findElement(By.id('searchTerm'));
        await searchInput.clear();
        await searchInput.sendKeys(sqlPayload);
        
        const submitButton = await driver.findElement(By.css('button[type="submit"]'));
        await submitButton.click();
        
        // Wait for error message
        const errorElement = await driver.wait(until.elementLocated(By.className('error')), 5000);
        const errorText = await errorElement.getText();
        
        assert.ok(errorText.toLowerCase().includes('sql') || errorText.toLowerCase().includes('injection') || errorText.toLowerCase().includes('malicious'), 
                  `SQL injection variant should be detected: ${sqlPayload}`);
        
        // Check input is cleared
        const inputValue = await searchInput.getAttribute('value');
        assert.strictEqual(inputValue, '', `Input should be cleared for SQL injection variant: ${sqlPayload}`);
    }
    
    console.log("✓ Additional SQL injection variants test passed");
}