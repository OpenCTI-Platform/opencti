import { cleanup } from '@testing-library/react';
import * as matchers from "@testing-library/jest-dom/matchers";
import { expect, afterEach, vi } from 'vitest';

import '@testing-library/jest-dom/vitest';

// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
global.jest = vi;


expect.extend(matchers);

afterEach(() => {
  cleanup();
});