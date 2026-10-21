import type { Locator, Page, TestInfo } from '@playwright/test';
import { expect } from '../fixtures/baseFixtures';

// The overview scrolls inside the application frame, so a full-page capture stops at the window: a taller window shows
// the first two rows of the overview layout, where the timeline sits next to its neighbour
const OVERVIEW_CAPTURE_HEIGHT = 1400;
// A drawer scrolls inside itself: the window grows to its content, up to this height
const DRAWER_CAPTURE_MAX_HEIGHT = 2000;
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

/**
 * Drawer holding `content`, one image pixel per CSS pixel. A drawer slides in from the right: it is captured once its
 * transition is over and it rests against the right edge of the window, in a window tall enough for its whole content
 * (the help of every field and the "Learn more" link at the bottom).
 */
export const captureDrawer = async (page: Page, testInfo: TestInfo, name: string, content: Locator) => {
  const viewport = page.viewportSize();
  const width = viewport?.width ?? 1440;
  const paper = page.locator('.MuiDrawer-paper').filter({ has: content });
  const settled = () => expect.poll(() => paper.evaluate((element) => element.getAnimations().length === 0
    && Math.round(element.getBoundingClientRect().right) >= document.documentElement.clientWidth), { timeout: SETTLE_TIMEOUT }).toBe(true);
  try {
    await settled();
    // The content scrolls in the last child of the drawer, under its header
    const contentBottom = await paper.evaluate((element) => {
      const scroller = element.lastElementChild;
      return scroller ? scroller.getBoundingClientRect().top + scroller.scrollHeight : element.scrollHeight;
    });
    const height = Math.min(DRAWER_CAPTURE_MAX_HEIGHT, Math.max(viewport?.height ?? 900, Math.ceil(contentBottom)));
    await page.setViewportSize({ width, height });
    await settled();
    await page.screenshot({ path: testInfo.outputPath(`case-timeline-${name}.png`), scale: 'css' });
  } finally {
    if (viewport) await page.setViewportSize(viewport);
  }
};
