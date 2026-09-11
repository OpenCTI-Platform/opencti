import type { TestingLibraryMatchers } from '@testing-library/jest-dom/matchers';

// `@testing-library/jest-dom` is the DOM matcher library (`toBeInTheDocument`,
// `toHaveAttribute`, ...); the "jest" in its name is historical and this project runs no
// Jest. The package ships its own Vitest augmentation, but as of 7.0.1 it still targets the
// single type parameter `Assertion<T>` of Vitest 4, so it no longer merges with the
// `Assertion<R, T>` of Vitest 5. The matchers are declared here against `Matchers`, the
// extension point Vitest 5 documents, until the package supports it upstream.
declare module 'vitest' {
  interface Matchers<R extends void | Promise<void> = void | Promise<void>> extends TestingLibraryMatchers<unknown, R> {}
}
