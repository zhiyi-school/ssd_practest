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

console.log(`Running password validation tests in '${environment}' environment`);
console.log(`Selenium URL: ${seleniumUrl}`);
console.log(`Server URL: ${serverUrl}`);

(async function runPasswordValidationTests() {
    let driver;

    try {
        console.log("Initializing WebDriver...");
        
        // Initialize the WebDriver with Chrome
        driver = await new Builder()
            .forBrowser('chrome')
            .usingServer(seleniumUrl)
            .build();

        console.log("WebDriver initialized successfully");

        // Test 1: Check if password input and login button exist
        await testFormElements(driver);
        
        // Test 2: Test short password rejection
        await testShortPassword(driver);
        
        // Test 3: Test common password rejection
        await testCommonPassword(driver);
        
        // Test 4: Test valid password login
        await testValidPassword(driver);
        
        // Test 5: Test welcome page elements
        await testWelcomePage(driver);
        
        // Test 6: Test logout functionality
        await testLogout(driver);

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

// Test 1: Home page has form with password input and login button
async function testFormElements(driver) {
    console.log("Test 1: Checking form elements...");
    
    await driver.get(serverUrl);
    
    const passwordInput = await driver.findElement(By.id('password'));
    const loginButton = await driver.findElement(By.css('button[type="submit"]'));
    
    assert.ok(passwordInput, 'Password input field should exist');
    assert.ok(loginButton, 'Login button should exist');
    
    console.log("✓ Form elements test passed");
}

// Test 2: OWASP password requirements - minimum 8 characters
async function testShortPassword(driver) {
    console.log("Test 2: Testing short password rejection...");
    
    await driver.get(serverUrl);
    
    const passwordInput = await driver.findElement(By.id('password'));
    await passwordInput.clear();
    await passwordInput.sendKeys('1234567'); // 7 characters
    
    const loginButton = await driver.findElement(By.css('button[type="submit"]'));
    await loginButton.click();
    
    const errorElement = await driver.wait(until.elementLocated(By.className('error')), 5000);
    const errorText = await errorElement.getText();
    
    assert.ok(errorText.includes('8'), 'Error message should mention 8 characters');
    
    console.log("✓ Short password rejection test passed");
}

// Test 3: Block common passwords
async function testCommonPassword(driver) {
    console.log("Test 3: Testing common password rejection...");
    
    await driver.get(serverUrl);
    
    const passwordInput = await driver.findElement(By.id('password'));
    await passwordInput.clear();
    await passwordInput.sendKeys('password');
    
    const loginButton = await driver.findElement(By.css('button[type="submit"]'));
    await loginButton.click();
    
    const errorElement = await driver.wait(until.elementLocated(By.className('error')), 5000);
    const errorText = await errorElement.getText();
    
    assert.ok(errorText.includes('common'), 'Error message should mention common password');
    
    console.log("✓ Common password rejection test passed");
}

// Test 4: Valid password goes to welcome page
async function testValidPassword(driver) {
    console.log("Test 4: Testing valid password login...");
    
    await driver.get(serverUrl);
    
    const passwordInput = await driver.findElement(By.id('password'));
    await passwordInput.clear();
    await passwordInput.sendKeys('ValidPass123!');
    
    const loginButton = await driver.findElement(By.css('button[type="submit"]'));
    await loginButton.click();
    
    await driver.wait(until.urlContains('welcome'), 10000);
    const currentUrl = await driver.getCurrentUrl();
    
    assert.ok(currentUrl.includes('welcome'), 'Should redirect to welcome page');
    
    console.log("✓ Valid password login test passed");
}

// Test 5: Welcome page shows password and has logout button
async function testWelcomePage(driver) {
    console.log("Test 5: Testing welcome page elements...");
    
    await driver.get(serverUrl);
    
    const passwordInput = await driver.findElement(By.id('password'));
    await passwordInput.clear();
    await passwordInput.sendKeys('TestPass123!');
    
    const loginButton = await driver.findElement(By.css('button[type="submit"]'));
    await loginButton.click();
    
    await driver.wait(until.urlContains('welcome'), 10000);
    
    const passwordDisplay = await driver.findElement(By.id('passwordDisplay'));
    const logoutButton = await driver.findElement(By.id('logoutBtn'));
    
    assert.ok(passwordDisplay, 'Password display element should exist');
    assert.ok(logoutButton, 'Logout button should exist');
    
    console.log("✓ Welcome page elements test passed");
}

// Test 6: Logout returns to home page
async function testLogout(driver) {
    console.log("Test 6: Testing logout functionality...");
    
    await driver.get(serverUrl);
    
    const passwordInput = await driver.findElement(By.id('password'));
    await passwordInput.clear();
    await passwordInput.sendKeys('LogoutTest123!');
    
    const loginButton = await driver.findElement(By.css('button[type="submit"]'));
    await loginButton.click();
    
    await driver.wait(until.urlContains('welcome'), 10000);
    
    const logoutButton = await driver.findElement(By.id('logoutBtn'));
    await logoutButton.click();
    
    await driver.wait(until.urlMatches(new RegExp(serverUrl + '/?$')), 5000);
    const currentUrl = await driver.getCurrentUrl();
    
    assert.ok(currentUrl.match(new RegExp(serverUrl + '/?$')), 'Should return to home page');
    
    console.log("✓ Logout functionality test passed");
}