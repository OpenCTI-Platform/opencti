import { cleanup } from '@testing-library/react';
import * as matchers from '@testing-library/jest-dom/matchers';
import { expect, afterEach, vi } from 'vitest';

// vitest.config.ts sets isolate: false, so one worker and one jsdom run many
// test files in a row. This file runs before each of them: undo what the
// previous file may have left.
//
// Modules and mocks are reset the way vitest does it itself between isolated
// files, which has no public API, hence the globals. vi.resetModules() alone
// keeps mocked modules, and so do module-level caches in node_modules: either
// would hold every previous file's module graph alive, ~14 MB a file, enough
// to exhaust the CI runner's memory over the suite.
type ModuleNode = { importers: Set<string>; meta?: object; file: string; evaluated: boolean; promise?: Promise<unknown> };
const vitestGlobals = globalThis as {
  __vitest_mocker__?: { reset: () => void; moduleRunner?: { concurrentModuleNodePromises: Map<string, Promise<unknown>> } };
  __vitest_worker__?: {
    evaluatedModules?: { idToModuleMap: Map<string, ModuleNode>; invalidateModule: (node: ModuleNode) => void };
  };
};
// Written against vitest 5.0.4. If a vitest upgrade renames one of these,
// fail here rather than silently skip the reset: mocks would leak between
// files and worker memory would grow until the run is killed.
const { __vitest_mocker__: mocker, __vitest_worker__: worker } = vitestGlobals;
const evaluatedModules = worker?.evaluatedModules;
if (!mocker?.moduleRunner || !evaluatedModules) {
  throw new Error(
    `setup-vitest.ts: vitest internal "${mocker?.moduleRunner ? '__vitest_worker__.evaluatedModules' : '__vitest_mocker__.moduleRunner'}" is missing. `
    + 'The per-file reset was written against vitest 5.0.4; adapt it to the installed version.',
  );
}
// A file can end while an import it started is still running: a React.lazy
// route it rendered and never awaited (settings/Root.test.tsx). That import
// would go on in this file, and the module runner hands a module it is still
// evaluating, its exports not assigned yet, to an importer it takes for a
// circular one: MarkdownField got MarkdownFieldBase as undefined that way.
// Let it finish before anything is reset or imported: its fetches first, then
// the evaluations they start, a macrotask apart. Real timers, or a fake
// setTimeout left by the previous file would never fire.
vi.useRealTimers();
const { concurrentModuleNodePromises: fetching } = mocker.moduleRunner;
const inFlight = () => [
  ...fetching.values(),
  ...[...evaluatedModules.idToModuleMap.values()]
    .filter((node) => node.promise && !node.evaluated && node.file !== import.meta.filename)
    .map((node) => node.promise),
];
for (let pending = inFlight(); pending.length; pending = inFlight()) {
  await Promise.allSettled(pending);
  await new Promise((resolve) => setTimeout(resolve));
}
mocker.reset();
vi.resetModules();
evaluatedModules.idToModuleMap.forEach((node, id) => {
  if (!id.startsWith('mock:') && !(node.meta && 'mockedModule' in node.meta)) return;
  evaluatedModules.invalidateModule(node);
  node.importers.clear();
});
vi.restoreAllMocks();
vi.unstubAllGlobals();
vi.unstubAllEnvs();
localStorage.clear();
sessionStorage.clear();
window.history.replaceState(null, '', '/');
[document.documentElement, document.body].forEach((element) => {
  [...element.attributes].forEach(({ name }) => element.removeAttribute(name));
});
document.body.replaceChildren();

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
