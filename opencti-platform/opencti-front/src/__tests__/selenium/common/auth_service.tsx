import { By, WebDriver } from 'selenium-webdriver';
import DriverService from './driver_service';
import { getElementWithTimeout, wait } from './action_service';
import { readConfigFile } from './file_service';

// OPTIMIZE: development.json is the the assumed configuration for testing.
// OPTIMIZE: will failover to test.json if not found.
const config = readConfigFile();
const BASE_SITE = config.app.base_site;
const BASE_PORT = config.app.port;
const USERNAME = config.app.admin.email;
const PASSWORD = config.app.admin.password;
const BASE_URL = `${BASE_SITE}:${BASE_PORT}/`;

/**
 * Logs the user in with a given username/password, else as admin.
 *
 * @param username
 * @param password
 */
export async function logIn_LocalStrategy(username = USERNAME, password = PASSWORD) {
  const driver: WebDriver = await new DriverService().driver;
  await driver.get(BASE_URL);

  // Click consent
  try {
    const consentCheck = await getElementWithTimeout(By.name('consent'), 2000);
    await wait(500);
    await consentCheck.click();
    // Login Form will auto scroll to the username/password fields
    await wait(1000);
    /* eslint no-console: ["error", { allow: ["warn", "error"] }] */
  } catch { console.warn('Warn: Could not find consent checkbox - could be currently disabled - continuing.....'); }
  // Click Login form items
  const usernameInput = await getElementWithTimeout(By.name('email'), 2000);
  const passwordInput = await getElementWithTimeout(By.name('password'), 2000);
  const submitButton = await getElementWithTimeout(
    By.xpath("//button[@type='submit']"),
  );

  // Enter username
  await usernameInput.click();
  await usernameInput.sendKeys(username);

  // Enter password
  await passwordInput.click();
  await passwordInput.sendKeys(password);

  // Login
  await submitButton.click();
}

/**
 * Logs the current user out.
 */
export async function logOut() {
  const driver: WebDriver = await new DriverService().driver;

  // Navigate to dashboard
  await driver.get(`${BASE_URL}dashboard`);
  const profileMenuButton = await getElementWithTimeout(
    By.id('profile-menu-button'),
  );
  // Open profile menu
  profileMenuButton.click();
  const logoutButton = await getElementWithTimeout(By.id('logout-button'));
  logoutButton.click();
}
