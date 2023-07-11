import * as R from 'ramda';
import { By, Key, Locator } from 'selenium-webdriver';
import {
  clickFab,
  clickNonClickable,
  getDropdownSelectorWithName,
  getElementWithTimeout,
  getXpathNodeWith,
  goToPath,
  replaceTextFieldValue,
  selectRandomFromDropdown,
  wait,
} from './action_service';
import { deselectExternalRef, extractExternalRef, selectRandomExternalRef } from './external_ref_service';

/**
 * Navigates to a Domain Object's overview page, or list displayer if no id is given.
 *
 * Example:
 *    await goToObjectOverview('locations', 'positions');
 *    // Navigates to <localhost:4000/dashboard/locations/positions/>
 *
 * @param objectCategory Used as the subpath when navigating to an object's overview
 * page. Examples are 'locations', 'entities', 'threats', etc.
 * @param objectType Used as the sub-subpath after the objectCategory. Examples are
 * 'positions', 'individuals', 'threat_actors', etc.
 * @param id Optional internal ID for the Object
 * @param waitMS Number of ms to wait after navigating to the page. Defaults to 2000 ms.
 */
export async function goToObjectOverview(objectCategory: string, objectType: string, id = '', waitMS = 2000) {
  await goToPath(`/dashboard/${objectCategory}/${objectType}/${id}`);
  await wait(waitMS); // Wait for page to load
}

/**
 * Tries to click on a Domain Object with the given name. Assumes that the current view
 * is the object overview page. Call goToObjectOverview before this function.
 *
 * @param name The name of the Domain Object to select.
 */
export async function selectObject(name: string) {
  try {
    const position = await getXpathNodeWith('text', name, { xpath: '/ancestor::a' });
    await clickNonClickable(position);
  } catch (err) {
    // Failed to find element with name.
    // TODO: Log errors like this and determine what to do.
    /* eslint no-console: ["error", { allow: ["warn", "error"] }] */
    console.warn('Error!', err);
  }
}

export interface SelectFieldsOptions {
  author?: boolean;
  marking?: boolean;
  externalRef?: boolean;
  country?: boolean;
  admin_area?: boolean;
}

export interface CreateOptions {
  latitude?: number;
  longitude?: number;
  select?: SelectFieldsOptions;
}

export async function selectFields(options: SelectFieldsOptions = {}) {
  // Select existing Author
  let author = '';
  if (options.author) {
    author = await selectRandomFromDropdown(
      getDropdownSelectorWithName('createdBy'),
      [
        'test individual', // Deleted when individual tests are finished
        'test position organization', // Deleted when position unlinked from temp org
      ],
    );
    await wait(250);
  }
  // Select existing Marking
  let marking = '';
  if (options.marking) {
    let n = 1;
    try {
      // Remove possible previously selected marking first
      const clearBtn = await getXpathNodeWith('data-testid', 'CancelIcon', { nth: 2, timeout: 1000 });
      n = 2;
      await clearBtn.getTagName();
      await clearBtn.click();
    } catch (ignore) {
      /* eslint no-console: ["error", { allow: ["warn", "error"] }] */
      console.warn('Error removing marking');
    }
    marking = await selectRandomFromDropdown(getDropdownSelectorWithName('objectMarking', n));
    await wait(250);
  }
  // Select existing External Ref
  let externalRef = '';
  if (options.externalRef) {
    externalRef = await selectRandomFromDropdown(getDropdownSelectorWithName('externalReferences'));
    await wait(250);
  }
  // Select existing Country
  let country = '';
  if (options.country) {
    country = await selectRandomFromDropdown(getDropdownSelectorWithName('country'));
    await wait(250);
  }
  // Select existing Administrative Area
  let admin_area = '';
  if (options.admin_area) {
    try {
      admin_area = await selectRandomFromDropdown(getDropdownSelectorWithName('administrative_area'));
      await wait(250);
    } catch {
      /* eslint no-console: ["error", { allow: ["warn", "error"] }] */
      console.warn(`Country "${country}" is too small to have an administrative area. No area was selected.`);
    }
  }
  // Return selected values
  return { author, marking, externalRef, country, admin_area };
}

/**
 * Enters latitude and longitude values for a domain object that supports location.
 */
export async function inputLatAndLong(latitude: string | number, longitude: string | number) {
  const lat = Number(latitude).toString();
  const long = Number(longitude).toString();
  const latField = await getXpathNodeWith('name', 'latitude');
  const longField = await getXpathNodeWith('name', 'longitude');
  await latField.click();
  await latField.sendKeys(lat);
  await longField.click();
  await longField.sendKeys(long);
}

/**
 * Creates a new Domain Object for the given category and type (subcategory) with the
 * given name and description. A callback function can be provided to perform additional
 * tasks before creating the object.
 *
 * Usage:
 *
 *     const { author, marking, externalRef } = await createDomainObject(
 *         'locations',
 *         'positions',
 *         'test position',
 *         'test position description',
 *         async () => {
 *             // do other domain-specific stuff here...
 *         },
 *     )
 *
 * @param objectCategory The category that the object type belongs to.
 * @param objectType The subcategory of the object.
 * @param name A unique name for the object.
 * @param description Some text to describe the object.
 * @param callback Optional function to be run if other items need to be created. Note
 * that this function MUST be defined as `async` or return an empty (void) Promise so
 * that it can be awaited.
 * @param options Optional settings to pass including what dropdown fields to select.
 * @returns Values randomly selected from dropdowns.
 */
export async function createDomainObject(
  objectCategory: string,
  objectType: string,
  name: string,
  description: string,
  options: CreateOptions = {},
  callback: (() => Promise<void>) | null = null,
) {
  await goToObjectOverview(objectCategory, objectType);
  await wait(500); // Wait for page to load
  await clickFab('Add');
  await wait(50); // Wait for sidebar menu to open

  // Fill name field
  const nameField = await getXpathNodeWith('name', 'name');
  await nameField.sendKeys(name);

  // Fill description field
  const descriptionField = await getXpathNodeWith('text', 'Description', { xpath: '/following-sibling::div//textarea' });
  await descriptionField.click();
  await descriptionField.sendKeys(description);

  if (options.latitude && options.longitude) {
    await wait(500);
    await inputLatAndLong(options.latitude, options.longitude);
  }

  // Execute callback if provided
  if (R.is(Function, callback)) {
    await callback();
  }
  await wait(500);

  // Select dropdown fields
  const selections = await selectFields({ ...options.select });

  // Click create button
  const createBtn = await getXpathNodeWith('text', 'Create', { nodePath: '//button' });
  await createBtn.click();

  return selections;
}

interface ReplaceLatLongData {
  latitude?: number | string;
  longitude?: number | string;
}
export async function replaceLatAndLong(data: ReplaceLatLongData = {}) {
  if (data.latitude) {
    const lat = Number(data.latitude).toString();
    const latField = await getXpathNodeWith('name', 'latitude');
    await latField.click();
    await wait(2000); // Wait for component update before attempting to edit
    await replaceTextFieldValue(latField, lat);
    await wait(500);
  }
  if (data.longitude) {
    const long = Number(data.longitude).toString();
    const longField = await getXpathNodeWith('name', 'longitude');
    await longField.click();
    await wait(2000); // Wait for component update before attempting to edit
    await replaceTextFieldValue(longField, long);
    await wait(500);
    longField.sendKeys(Key.TAB);
  }
}

interface ValueOptions {
  description?: string;
  latitude?: string | number;
  longitude?: string | number;
  admin_area?: string;
  country?: string;
  author?: boolean | string;
  marking?: boolean | string;
  externalRef?: boolean | string;
}

/**
 * Checks that a WebElement contains the given text value or that the element exists.
 *
 * @param locator The selector for the WebElement.
 * @param value If undefined, the check is skipped. If boolean, the value is not checked,
 * but only the existence of text. If a string, the exact value is compared.
 * @returns
 */
async function checkValue(locator: Locator, value: string | number | boolean | undefined) {
  if (value === undefined) return null;
  const valueDisplay = await getElementWithTimeout(locator);
  const valueText = await valueDisplay.getText();
  if (value === true) {
    expect(valueText).toBeDefined();
  } else if (R.is(String, value)) {
    expect(valueText.toLowerCase()).toBe(value.toLowerCase());
  } else if (R.is(Number, value)) {
    expect(valueText).toBe(String(value));
  }
  return null;
}

/**
 * Checks values for a domain object that was newly created or updated.
 * If a value is not provided because it is checked by something else, then that value
 * check is simply ignored by the checkValue function.
 */
export async function checkValues(values: ValueOptions = {}) {
  // Description
  await checkValue(By.xpath('//*[*[text()="Description"]]//p'), values.description);
  // Latitude
  await checkValue(By.xpath('//*[*[text()="Latitude"]]//p'), values.latitude);
  // Longitude
  await checkValue(By.xpath('//*[*[text()="Longitude"]]//p'), values.longitude);
  // Author
  await checkValue(By.xpath('//*[@id="createdBy"]/a'), values.author);
  // Object marking
  // Using last() to check the last added value in cases where there's multiple object markings
  await checkValue(By.xpath('(//*[@id="objectMarking"]//span[contains(@class, "MuiChip-label")])[last()]'), values.marking);
  // External reference
  // TODO: possible fix needed if more than 1 ext ref list item
  await checkValue(By.xpath('//ul//span'), values.externalRef);
  // Area link
  await checkValue(By.xpath(`//div[//span[text()="Area"]]/div[text()="${values.admin_area}"]`), values.admin_area);
  // Country link
  await checkValue(By.xpath(`//div[//span[text()="Country"]]/div[text()="${values.country}"]`), values.country);
}

export interface UpdateData extends CreateOptions {
  name?: string;
  description?: string;
  oldExternalRef?: string;
}

/**
 * Navigates to the target domain object by using the given category, type, and name.
 *
 * @param objectCategory The category that the object type belongs to.
 * @param objectType The subcategory of the object.
 * @param name A unique name for the object.
 * @param data Field values that should be updated. See UpdateData for field names.
 * @param callback Optional function to be run if other items need to be created. Note
 * that this function MUST be defined as `async` or return an empty (void) Promise so
 * that it can be awaited.
 * @returns the randomly selected field values that were chosen.
 */
export async function updateDomainObject(
  objectCategory: string,
  objectType: string,
  name: string,
  data: UpdateData,
  callback: (() => Promise<void>) | null = null,
) {
  await goToObjectOverview(objectCategory, objectType);
  await wait(500); // Wait for page to load
  await selectObject(name);
  await wait(1000); // Wait for object page to load
  let externalRef = '';
  if (data.oldExternalRef) {
    // Remove the existing external ref link
    await deselectExternalRef(extractExternalRef(data.oldExternalRef)?.id ?? '');
    await wait(500); // Wait for component reload
    if (data.select?.externalRef) {
      // Select a new random external ref link
      externalRef = await selectRandomExternalRef();
      await wait(1000);
    }
    // Close the external ref edit menu
    await clickFab('Close', false, 2);
    await wait(500); // Wait for sidebar menu to close
  }
  await clickFab('Edit');
  await wait(100); // Wait for edit menu to open

  // Process any data updates
  if (data.name) {
    // Fill name field
    const nameField = await getXpathNodeWith('name', 'name');
    // Remove old name first
    await replaceTextFieldValue(nameField, data.name);
    await wait(500);
  }
  if (data.description) {
    // Fill description field
    const descriptionField = await getXpathNodeWith('text', 'Description', { xpath: '/following-sibling::div//textarea' });
    await descriptionField.click();
    await wait(100);
    // Remove old description first
    await replaceTextFieldValue(descriptionField, data.description);
    await wait(500);
  }
  // Handle latitude and longitude values
  if (data.latitude || data.longitude) {
    await wait(500);
    await replaceLatAndLong(data);
    await wait(500);
  }
  // Select dropdown fields
  const selections = await selectFields({ ...data.select, externalRef: false });

  // Execute callback if provided
  if (R.is(Function, callback)) {
    await callback();
  }

  return { ...selections, externalRef };
}

/**
 * Assuming that the current view is a Stix Domain Object overview, click the
 * ellipsis (more options) button, click 'Delete', and then confirm 'Delete'.
 */
export async function deleteDomainObject() {
  try {
    const moreOptions = await getXpathNodeWith('data-testid', 'MoreVertIcon', { xpath: '/..' });
    await moreOptions.click();

    const deleteBtn = await getXpathNodeWith('text', 'Delete', { nodePath: '//li' });
    await clickNonClickable(deleteBtn);

    const confirmDelete = await getXpathNodeWith('text', 'Delete', { nodePath: '//button' });
    await clickNonClickable(confirmDelete);
  } catch (err) {
    // Failed to find element with name.
    // TODO: Log errors like this and determine what to do.
    /* eslint no-console: ["error", { allow: ["warn", "error"] }] */
    console.warn('Error!', err);
  }
}

/**
 * Assuming that the current view is a Stix Domain Object overview, click the
 * "Knowledge" tab. If selectView is given, then additionally select a view Tab from the
 * right-hand nav sidebar in the Knowledge view.
 */
export async function goToKnowledgeView(selectView = '') {
  // Note: When TopBar is refactored, there will likely not be two toolbars and thus no
  // need to select the second Knowledge tab element.
  const knowledgeTab = await getXpathNodeWith('text', 'Knowledge', { nth: 2 });
  await clickNonClickable(knowledgeTab);
  if (selectView) {
    await wait(500); // Allow the Knowledge view to load
    const viewTab = await getXpathNodeWith('text', 'Organizations', { xpath: '/ancestor::a' });
    await clickNonClickable(viewTab);
  }
}
export async function goToKnowledgeViewCountries(selectView = '') {
  // Note: When TopBar is refactored, there will likely not be two toolbars and thus no
  // need to select the second Knowledge tab element.
  const knowledgeTab = await getXpathNodeWith('text', 'Knowledge', { nth: 2 });
  await clickNonClickable(knowledgeTab);
  if (selectView) {
    await wait(500); // Allow the Knowledge view to load
    const viewTab = await getXpathNodeWith('text', 'Countries', { xpath: '/ancestor::a' });
    await clickNonClickable(viewTab);
  }
}
