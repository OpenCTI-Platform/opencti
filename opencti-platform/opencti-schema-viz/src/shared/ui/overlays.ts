/**
 * A library popover (Select, Menu, Combobox list, Tooltip) is open: Escape belongs to it first.
 * Read it from a capture-phase listener, before Radix removes the popover on that same key.
 */
export const isPopoverOpen = () => document.querySelector('[data-radix-popper-content-wrapper]') !== null;
