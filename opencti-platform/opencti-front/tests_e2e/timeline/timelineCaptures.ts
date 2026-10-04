import type { Page, TestInfo } from '@playwright/test';

// The overview scrolls inside the application frame, so a full-page capture stops at the window: a taller window shows
// the first two rows of the overview layout, where the timeline sits next to its neighbour
const OVERVIEW_CAPTURE_HEIGHT = 1400;
const SETTLE_TIMEOUT = 10000;

/**
 * Overview of an entity with its first two rows, one image pixel per CSS pixel. The caller waits for the state it
 * shows; the capture then waits for the loaders of the other widgets, and a widget still loading after the timeout is
 * captured as it is (a capture is evidence for the documentation, the assertions stay in the test).
 */
export const captureOverview = async (page: Page, testInfo: TestInfo, name: string) => {
  const viewport = page.viewportSize();
  await page.setViewportSize({ width: viewport?.width ?? 1440, height: OVERVIEW_CAPTURE_HEIGHT });
  try {
    await page.waitForFunction(() => document.querySelector('[role="progressbar"]') === null, undefined, { timeout: SETTLE_TIMEOUT })
      .catch(() => undefined);
    await page.screenshot({ path: testInfo.outputPath(`case-timeline-${name}.png`), scale: 'css' });
  } finally {
    if (viewport) await page.setViewportSize(viewport);
  }
};
