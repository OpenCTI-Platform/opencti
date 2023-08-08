import 'chromedriver';
import { Builder, WebDriver } from 'selenium-webdriver';
import chrome from 'selenium-webdriver/chrome';
import config from '../../config.json' assert { type: 'json' };

const windowSize = {
  height: config.windowSize.height,
  width: config.windowSize.width,
};
const capabilities = {
  browser: config.capabilities.browser,
  browser_version: config.capabilities.browser_version,
  resolution: `${windowSize.height}x${windowSize.width}`,
};

export default class DriverService {
  static instance: DriverService;

  static driver: null | WebDriver;

  constructor() {
    if (!(DriverService.instance instanceof DriverService)) {
      DriverService.instance = this;
    }
    // return DriverService.instance;
  }

  /**
   * Makes or return the existing Selenium WebDriver.
   *
   * @returns The Selenium WebDriver.
   */
  /* eslint no-underscore-dangle: 0 */
  /* eslint class-methods-use-this: 0 */
  private _raiseDriver() {
    return (async () => {
      let chromeOptions = null as unknown as chrome.Options;
      if (!(DriverService.driver instanceof WebDriver)) {
        if (config.headless) {
          chromeOptions = new chrome.Options().headless().windowSize(windowSize);
          // Fix Floss manager not present, cannot set Floss enable/disable on Linux Docker images launched from CI/CD
          chromeOptions.addArguments('--headless=new');
        } else {
          chromeOptions = new chrome.Options().windowSize(windowSize);
        }
        // Full list of switches at: https://peter.sh/experiments/chromium-command-line-switches/
        chromeOptions.addArguments('--disable-gpu'); // overcome limited resources of CI/CD pipeline images
        chromeOptions.addArguments('--disable-dev-shm-usage'); // overcome limited resources of CI/CD pipeline images
        chromeOptions.addArguments('--disable-extensions'); // disabling extensions not required for testing
        chromeOptions.addArguments('--no-sandbox'); // Bypass OS security model - NOT RECOMMENDED
        // chromeOptions.addArguments("--disable-software-rasterizer"); // Allow GPU to perform Raster
        // chromeOptions.setChromeBinaryPath("/usr/bin/chromium-browser");

        DriverService.driver = await new Builder()
          .withCapabilities(capabilities)
          .forBrowser(capabilities.browser)
          .setChromeOptions(chromeOptions)
          .build();
      }
      return DriverService.driver;
    })();
  }

  /**
   * Safely closes the WebDriver.
   */
  static async teardownDriver() {
    if (DriverService.driver instanceof WebDriver) {
      await DriverService.driver.quit();
      DriverService.driver = null;
    }
  }

  /**
   * Public getter for the driver.
   *
   * @readonly
   * @type {Promise<WebDriver>}
   * @memberof DriverService
   */
  get driver(): Promise<WebDriver> {
    if (DriverService.driver instanceof WebDriver) {
      return new Promise((resolve) => {
        resolve(DriverService.driver as WebDriver);
      });
    }
    return this._raiseDriver();
  }
}
