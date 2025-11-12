import { cleanup } from '@testing-library/react';
import * as matchers from "@testing-library/jest-dom/matchers";
import { expect, afterEach, vi } from 'vitest';

import '@testing-library/jest-dom/vitest';

// biome-ignore lint/suspicious/noTsIgnore: disable ts-ignore
// @ts-ignore
global.jest = vi;


expect.extend(matchers);

afterEach(() => {
  cleanup();
});