import { Locator, Page } from '@playwright/test';

type TextFieldPageModelType = 'text' | 'text-area' | 'text-area-direct' | 'rich-content' | 'text-no-label' | 'search';

export default class TextFieldPageModel {
  private readonly inputLocator: Locator;
  private readonly parentLocator: Locator;

  /**
   * The field's own root, derived from the input rather than from the label.
   *
   * `getByText(label).locator('..')` used to reach it, because MUI puts the
   * <label> as a direct child of the FormControl that also holds the helper
   * text. The library Input wraps its label in a row of its own, so that
   * parent is the label row and the helper text is a level above it — which is
   * why an assertion on 'This field is required' stopped resolving.
   *
   * Two hops up from the input lands on the field root under BOTH engines
   * (library: input → div.relative → root; MUI: input → InputBase → FormControl),
   * and unlike widening the search it stays scoped to this one field, so a
   * message belonging to a sibling field can never satisfy the assertion.
   */
  private static fieldRootOf(input: Locator) {
    return input.locator('..').locator('..');
  }

  constructor(
    readonly page: Page,
    label: string,
    type: TextFieldPageModelType,
    readonly rootLocator?: Locator,
  ) {
    const root = rootLocator ?? page.locator('body');
    if (type === 'text-area') {
      this.parentLocator = root.getByText(label).locator('../../../..');
      this.inputLocator = this.parentLocator.getByTestId('text-area');
    } else if (type === 'text-area-direct') {
      this.parentLocator = root;
      this.inputLocator = root.getByTestId('text-area');
    } else if (type === 'rich-content') {
      this.parentLocator = root.getByText(label).locator('../..');
      this.inputLocator = this.parentLocator.getByLabel('Editing area: main');
    } else if (type === 'search') {
      // The design-system SearchField renders <input type="search">, which maps
      // to the ARIA searchbox role, not textbox. Its own type, rather than a
      // widened 'text-no-label', because the other three consumers of that type
      // are ordinary text inputs and must keep matching textbox.
      this.inputLocator = root.getByRole('searchbox', { name: label });
      this.parentLocator = root.getByText(label).locator('..');
    } else if (type === 'text-no-label') {
      this.inputLocator = root.getByRole('textbox', { name: label });
      this.parentLocator = TextFieldPageModel.fieldRootOf(this.inputLocator);
    } else {
      // `.and(control)`: `getByLabel` matches accessible names by SUBSTRING, and
      // the library's number stepper ships two buttons named "Increase value" /
      // "Decrease value". On the observable creation form, whose own field is
      // labelled `value`, the lookup went from one match to three. Constraining
      // to the elements this model is actually about — the form control — drops
      // the buttons without touching the label semantics, and without renaming
      // anything on either side.
      this.inputLocator = root.getByLabel(label).and(root.locator('input, textarea'));
      this.parentLocator = TextFieldPageModel.fieldRootOf(this.inputLocator);
    }
  }

  get() {
    return this.inputLocator;
  }

  value() {
    return this.inputLocator.inputValue();
  }

  async clear() {
    await this.inputLocator.clear();
  }

  async fill(input: string, clear = true) {
    await this.inputLocator.click();
    if (clear) await this.clear();
    return this.inputLocator.fill(input);
  }

  getByText(input: string) {
    return this.parentLocator.getByText(input);
  }
}
