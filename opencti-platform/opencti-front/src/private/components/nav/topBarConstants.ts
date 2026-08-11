/**
 * Geometry the product owns for the design-system `Header`. The library ships
 * no positioning and publishes its height as a custom property it does not
 * declare, so both live here rather than being restated at each site.
 */

/** Search window, aligned with the OpenAEV pilot for cross-product consistency. */
export const TOP_BAR_SEARCH_MIN_WIDTH = 200;
export const TOP_BAR_SEARCH_MAX_WIDTH = 500;

/**
 * The bar's height. `--fds-header-height` is the hook the library publishes on
 * `Header` without declaring it; 68px is the library's own fallback, restated
 * here so every product site resolves the same way.
 */
export const TOP_BAR_HEIGHT_FALLBACK = 68;
export const TOP_BAR_HEIGHT = `var(--fds-header-height, ${TOP_BAR_HEIGHT_FALLBACK}px)`;
