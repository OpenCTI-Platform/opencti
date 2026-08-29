import { cleanup } from '@testing-library/react';
import * as matchers from "@testing-library/jest-dom/matchers";
import { expect, afterEach, vi } from 'vitest';

import '@testing-library/jest-dom/vitest';

// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
global.jest = vi;


// jsdom ships no ResizeObserver. The Radix primitives behind the design-system
// Switch, Checkbox and Radio measure their control with one (their hidden bubble
// input calls useSize), so any test rendering one of them throws without this
// stub. Guarded so a real implementation always wins.
if (!('ResizeObserver' in globalThis)) {
  class ResizeObserverStub {
    observe() {}

    unobserve() {}

    disconnect() {}
  }
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  globalThis.ResizeObserver = ResizeObserverStub;
}

expect.extend(matchers);

afterEach(() => {
  cleanup();
});
// jsdom implements neither the Pointer Capture API nor scrollIntoView, and
// Radix — which the library Select and Combobox are built on — calls both while
// opening a panel. Without these the trigger throws
// `target.hasPointerCapture is not a function` and no listbox is ever rendered,
// so any test that opens a converted Select fails for a reason that has nothing
// to do with the component. Stubbed here rather than per test file: 113 Select
// mounts moved onto Radix in this migration.
if (!Element.prototype.hasPointerCapture) {
  Element.prototype.hasPointerCapture = () => false;
}
if (!Element.prototype.setPointerCapture) {
  Element.prototype.setPointerCapture = () => {};
}
if (!Element.prototype.releasePointerCapture) {
  Element.prototype.releasePointerCapture = () => {};
}
if (!Element.prototype.scrollIntoView) {
  Element.prototype.scrollIntoView = () => {};
}
