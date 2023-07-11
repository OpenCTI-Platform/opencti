import * as R from 'ramda';
import { By, Key, Locator, WebDriver, WebElement, until } from 'selenium-webdriver';
import DriverService from './driver_service';
import { readConfigFile } from './file_service';

const LONG_TIMEOUT = 10000;
const MED_TIMEOUT = 10000;
const SHORT_TIMEOUT = 2000;

/**
 * Waits until an element is located. Eventually times out.
 *
 * @param locator The element to locate.
 * @param timeout How long to wait in ms. Defaults to 5s.
 * @returns The located element
 */
export async function getElementWithTimeout(locator: Locator, timeout = MED_TIMEOUT) {
  const driver: WebDriver = await new DriverService().driver;
  const element = await driver.wait(until.elementLocated(locator), timeout);
  driver.executeScript('arguments[0].scrollIntoView(true)', element);
  return element;
}

/**
 * Given an element's ID, return it's child elements.
 *
 * @param locator ID of parent element.
 * @param timeout How long to wait in ms. Defaults to 2s.
 * @returns A list of the child elements
 */
export async function getSubElementsWithTimeout(
  locator: Locator,
  timeout = SHORT_TIMEOUT,
): Promise<WebElement[]> {
  const driver: WebDriver = await new DriverService().driver;
  const element: WebElement = await driver.wait(
    until.elementLocated(locator),
    timeout,
  );
  driver.executeScript('arguments[0].scrollIntoView(true)', element);
  const childElements = element.findElements(By.xpath('./child::*'));
  return childElements;
}

/**
 * Returns the appropriate simple xpath predicate expression for supported names. If the
 * given selector already has the '@' or '()' characters, no extra processing is done.
 *
 * Usage: To be used inside the predicate of an xpath expression: `//*[${in here}]`.
 *
 * Examples:
 *
 *     // select by id: <div id="abc"></div>
 *     `//*[${xpathPredicate(id, 'abc')}]` => '//*[@id="abc"]'
 *     // select by name:
 *     `//*[${xpathPredicate(name, 'abc')}]` => '//*[@name="abc"]'
 *     // select by text:
 *     `//*[${xpathPredicate(text, 'abc')}]` => '//*[text()="abc"]'
 *
 * @param selector Any valid attribute selector or 'text' for 'text()'.
 * @param value Any string value to be used to the right of the compare operator. Can be
 * empty.
 * @param compare One of the '=', '!=', '>', '<', '>=', or '<=' operators. Can be empty.
 * Default is '='.
 * @returns A string containing the selector, comparison operator, and value if all are
 * provided. Only the selector is returned if the selector is complete.
 */
function xpathPredicate(
  selector: string,
  value: string | number = '',
  compare: '=' | '!=' | '>' | '<' | '>=' | '<=' | '' = '=',
) {
  // First, determine if the selector is already complete
  if (selector.includes('(') || selector.includes('[')) {
    return selector;
  }
  const valString: string = (value && Number.isNaN(Number(value))) ? `"${value}"` : String(value);
  const comparison = (value && compare) || '';
  if (selector.startsWith('@')) {
    return `${selector}${comparison}${valString}`;
  }
  // Second, determine if the selector matches knnown functions
  const knownFunctions = ['text', 'last', 'position'];
  if (knownFunctions.includes(selector)) {
    return `${selector}()${comparison}${valString}`;
  }
  // Finally, the selector is just a simple attribute selector
  return `@${selector}${comparison}${valString}`;
}

/**
 * Given an element's identifier, find a subelement with the specified tag.
 *
 * Examples:
 *
 *     // Known element with id="xyz", get its child textarea
 *     getSubElementWithTimeout('id', 'xyz', 'textarea');
 *     // Known element with name="abc", get its child paragraph
 *     getSubElementWithTimeout('name', 'abc', 'p');
 *
 * @param selector Attribute selector used to identify the target element.
 * @param identifier Value used to identify the target element.
 * @param subelement Tag of child element to find.
 * @param timeout How long to wait in ms. Defaults to 2s.
 * @returns The located element
 */
export async function getSubElementWithTimeout(
  selector: string,
  identifier: string,
  subelement: string,
  timeout = SHORT_TIMEOUT,
) {
  const driver: WebDriver = await new DriverService().driver;
  const locator = By.xpath(`//*[${xpathPredicate(selector, identifier)}]//${subelement}`);
  const element = await driver.wait(until.elementLocated(locator), timeout);
  driver.executeScript('arguments[0].scrollIntoView(true)', element);
  return element;
}

/**
 * Clicks on any element, even if it's not a clickable button.
 * Useful for clicking on tags that route elsewhere, but aren't
 * considered an HTML button, such as some <a> tags.
 *
 * @param element Element to click on.
 */
export async function clickNonClickable(element: WebElement) {
  const driver: WebDriver = await new DriverService().driver;
  await driver.executeScript('arguments[0].click()', element);
}

/**
 * Wait for a given amount of time.
 *
 * @param time How long to wait, in ms. Defaults to 2s.
 */
export async function wait(time = SHORT_TIMEOUT) {
  await new Promise((resolve) => {
    setTimeout(resolve, time);
  });
}

/**
 * Selects a random element from a dropdown.
 *
 * If `noSelect` is provided a list of string values, the option randomly selected from
 * the dropdown is compared against the given values and another random selection is
 * attempted if the selection matches any of the given values.
 *
 * @param inputLocator The locator for the dropdown.
 * @param noSelect A list of values to avoid selecting.
 * @returns The text of the selected option.
 */
export async function selectRandomFromDropdown(
  inputLocator: Locator,
  noSelect: string[] = [],
): Promise<string> {
  // Open the Dropdown and click select a random option
  const inputDropdown = await getElementWithTimeout(inputLocator);
  try {
    await inputDropdown.click();
  } catch {
    await clickNonClickable(inputDropdown);
  }
  await wait(500); // Wait for listbox to open
  const inputOptions: WebElement[] = await getSubElementsWithTimeout(
    By.xpath("//ul[@role='listbox']"),
    LONG_TIMEOUT,
  );
  let randomOption: WebElement = inputOptions[Math.floor(Math.random() * inputOptions.length)];
  let selectionText = await randomOption.getText();
  if (noSelect.length > 0) {
    // Select another random value if current selection is not allowed
    /* eslint-disable no-await-in-loop */
    while (noSelect.includes(selectionText)) {
      randomOption = inputOptions[Math.floor(Math.random() * inputOptions.length)];
      selectionText = await randomOption.getText();
    }
    /* eslint-enable no-await-in-loop */
  }
  await clickNonClickable(randomOption);
  // Close the dropdown
  return selectionText;
}

interface SelectionOptions {
  nodePath?: string;
  xpath?: string;
  nth?: number;
  timeout?: number;
}

/**
 * Selects an element with the given identifier by building an xpath expression.
 *
 * Examples:
 *
 *     // Equivalent of '//*[text()="Not a button"]/ancestor::a'
 *     getXpathNodeWith('text', 'Not a button', { xpath: '/ancestor::a' });
 *     // Equivalent of '//*[@aria-label="does something"]'
 *     getXpathNodeWith('aria-label', 'does something');
 *     // Equivalent of '//ul/li[last() - 1]'
 *     getXpathNodeWith('last() - 1', { nodePath: '//ul/li' });
 *
 * @param selector An xpath predicate selector to use with the given identifier.
 * Examples include 'id', 'text', 'name', etc.
 * @param identifier The identifier to use with the xpath predicate selector.
 * @param options.elementPath Any valid xpath node path. Default is '//*'.
 * @param options.xpath Additional xpath selector to append to the text selection xpath.
 * Must start with '/'.
 * @param options.nth The nth element occurrence to select. Defaults to 1.
 * @param options.timeout How long to wait in ms. Defaults to 5s.
 */
export async function getXpathNodeWith(selector: string, identifier: string, options: SelectionOptions = {}) {
  const elementPath = options?.nodePath || '//*';
  const xpath = options?.xpath || '';
  const nth = options?.nth || 1;
  const timeout = options?.timeout || MED_TIMEOUT;
  const predicate = xpathPredicate(selector, identifier);
  const xpathNode = await getElementWithTimeout(By.xpath(`(${elementPath}[${predicate}]${xpath})[${nth}]`), timeout);
  return xpathNode;
}

/**
 * Builds a selenium selector by searching for an input with the given name and its child
 * button to activate the dropdown menu list. Pass the return value directly to
 * `selectRandomFromDropdown`.
 *
 * @param name The name of the dropdown menu field to open.
 * @param nth In the case of multiple instances (e.g., marking), pick the nth instance.
 * @returns a Locator selector for a WebElement.
 */
export function getDropdownSelectorWithName(name: string, nth = 1): Locator {
  return By.xpath(`(//*[input[@name="${name}"]]//button[@aria-label="Open"])[${nth}]`);
}

/** Returns given value without the given prefix. */
function removePrefix(value: string, prefix: string) {
  return value.startsWith(prefix) ? value.substring(prefix.length) : value;
}

/** Returns the given value with the given prefix prepended. */
function ensurePrefix(value: string, prefix: string) {
  return !value.startsWith(prefix) ? `${prefix}${value}` : value;
}

/**
 * Navigates to a given page path relative to the site's base URL.
 *
 * @param path A relative URL path to be appended to the baseUrl. May start with '/'.
 * @param query An optional query string. May start with '?'.
 * @param endpoint A hostname and port combination to serve as the base of the URL.
 * Defaults to the configured site endpoint in development.json.
 */
export async function goToPath(path: string, query = '', endpoint = '') {
  const driver: WebDriver = await new DriverService().driver;
  const defaultEndpoint = readConfigFile().app.base_url;
  await driver.get(`${endpoint || defaultEndpoint}${removePrefix(path, '/')}${ensurePrefix(query, '?')}`);
}

/**
 * Reloads the page by navigating to the current URL.
 */
export async function refreshCurrentPage() {
  const driver: WebDriver = await new DriverService().driver;
  await driver.get(await driver.getCurrentUrl());
}

/**
 * Selects and clicks the Floating Action Button (FAB) element identified by its label.
 *
 * @param label The aria-label attribute value for the element.
 * @param clickable If true, uses the built-in click() method for the object. Otherwise,
 * uses the clickNonClickable helper function.
 * @param nth If multiple FABs exist in the view, determines which one to select.
 */
export async function clickFab(label = 'Add', clickable = true, nth = 1) {
  const fab = await getXpathNodeWith('aria-label', label, { nodePath: '//button', nth });
  if (clickable) {
    await fab.click();
  } else {
    await clickNonClickable(fab);
  }
}

/**
 * Ensures that the value for the given locator either exists or matches the given value.
 * If value is true, simply checks that there is some value set for the locator. If value
 * is a string, then expects that the locator's value is exactly the given value string.
 *
 * @param locator Some selenium Locator instance (By.id, By.name, By.xpath, etc.)
 * @param value Either true or a string to match against the locator's value.
 */
export async function checkValue(locator: Locator, value: string | boolean | undefined) {
  if (value === undefined) return null;
  const valueDisplay = await getElementWithTimeout(locator);
  const valueText = await valueDisplay.getText()
    || await valueDisplay.getAttribute('value');
  if (value === true) {
    expect(valueText).toBeDefined();
  } else if (R.is(String, value)) {
    expect(valueText).toBe(value);
  }
  return null;
}

/**
 * Replaces the existing text within an input field by selecting all previous input in
 * the input element and replacing it with a new value.
 *
 * @param element Any input or textarea WebElement.
 * @param newVal Some string to replace the current text in the given element.
 */
export async function replaceTextFieldValue(element: WebElement, newVal: string) {
  await element.sendKeys(Key.chord(Key.SHIFT, Key.ARROW_UP), Key.BACK_SPACE, newVal);
}
