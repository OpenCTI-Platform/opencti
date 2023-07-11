import { By, Key, WebElement } from 'selenium-webdriver';
import { clickFab, clickNonClickable, getSubElementsWithTimeout, getXpathNodeWith, wait } from './action_service';

/**
 * Opens the external reference menu and deselects the currently selected external ref.
 * This assumes that the current page is a Domain Object overview and that the named
 * external ref is linked to the Domain Object.
 */
export async function deselectExternalRef(externalRef: string) {
  if (!externalRef) return;
  // Open the external reference menu
  await clickFab('Add', false);
  await wait(1000); // Wait for sidebar menu to open

  // Filter for the external ref
  const searchBar = await getXpathNodeWith('placeholder', 'Search...', { nth: 3 });
  await searchBar.getTagName();
  await searchBar.sendKeys(`"${externalRef}"`, Key.RETURN);
  await wait(250);
  // Deselect the currently selected external ref
  const selectedRef = await getXpathNodeWith('data-testid', 'CheckCircleIcon');
  await selectedRef.click();
  await wait(250);
  // Clear the search bar
  await searchBar.sendKeys(Key.chord(Key.SHIFT, Key.ARROW_UP), Key.BACK_SPACE, Key.RETURN);
}

/**
 * Selects a random visible external reference entity from the list. To be used
 * after opening up the external ref edit menu from a Domain Object overview.
 */
export async function selectRandomExternalRef() {
  const inputOptions: WebElement[] = await getSubElementsWithTimeout(
    By.xpath('//div[@id="external-reference-list"]//ul'),
  );
  const randomOption: WebElement = inputOptions[Math.floor(Math.random() * inputOptions.length)];
  const selected = await randomOption.getText();
  await clickNonClickable(randomOption);
  return selected;
}

/**
 * Retrieves an external reference name from a selected value. The expected patterns for
 * the `externalRef` value are:
 * - `[{external_ref_name}] {external_ref_id}`
 * - `{external_ref_name} ({external_ref_id})`
 */
export function extractExternalRef(externalRef: string) {
  if (!externalRef) return null;
  if (externalRef.startsWith('[') && externalRef.includes(']')) {
    const [name, id] = externalRef.split('] ');
    return {
      name: name.substring(1),
      id,
    };
  } if (externalRef.includes('(') && externalRef.endsWith(')')) {
    const [name, id] = externalRef.split(' (');
    return {
      name,
      id: id.replace(')', ''),
    };
  }
  return null;
}
