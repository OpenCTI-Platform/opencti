import 'chromedriver';
import { By, WebDriver, until } from 'selenium-webdriver';
import DriverService from './common/driver_service';
import { getElementWithTimeout } from './common/action_service';
import { logIn_LocalStrategy, logOut } from './common/auth_service';
import { readConfigFile } from './common/file_service';

describe('Authentication workflow', () => {
  // OPTIMIZE: development.json is the the assumed configuration for testing.
  // OPTIMIZE: will failover to test.json if not found.
  // const config = readJsonFile(getGQLPath('development.json', 'config'));
  const config = readConfigFile();
  const BASE_SITE = config.app.base_site;
  const BASE_PORT = config.app.port;
  const USERNAME = config.app.admin.email;
  const BASE_URL = `${BASE_SITE}:${BASE_PORT}/`;

  /**
   * Here we bypass TypeScript a bit, so that we can later
   * more conveniently access the variables.
   */
  let driver = null as unknown as WebDriver;

  /**
   * Before starting the first test, we get our singleton driver.
   */
  beforeAll(async () => {
    driver = await new DriverService().driver;
  });

  afterAll(async () => {
    await DriverService.teardownDriver();
  });

  test('LocalStrategy - validate login with email and password', async () => {
    await logIn_LocalStrategy();
    // Wait for dashboard to load and open profile
    await driver.wait(until.elementLocated(By.css('header.MuiAppBar-root')));
    await driver.get(`${BASE_URL}dashboard/profile`);
    // Verify logged in user is correct
    const userEmail = await getElementWithTimeout(By.name('user_email'));
    expect(await userEmail.getAttribute('value')).toBe(USERNAME);
  });

  test('validate authenticated users ability to logout', async () => {
    await logOut();
    // Check that the current page has login elements
    let element;
    try {
      element = await getElementWithTimeout(By.name('consent'), 2000);
    } catch {
      element = await getElementWithTimeout(By.name('email'));
    }
    expect(element).not.toBeNull();
  });
});
