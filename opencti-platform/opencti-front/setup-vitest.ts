import { cleanup } from '@testing-library/react';
import * as matchers from "@testing-library/jest-dom/matchers";
import { expect, afterEach, vi } from 'vitest';

import '@testing-library/jest-dom/vitest';

// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
global.jest = vi;


// jsdom ships no ResizeObserver. The Radix primitives behind the design-system
// Checkbox, Radio and Switch measure their control with one (their hidden bubble
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