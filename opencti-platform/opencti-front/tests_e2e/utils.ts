import { Page } from '@playwright/test';

const fakeDate = async (page: Page, dateString: string) => {
  // Pick the new/fake "now" for you test pages.
  const fakeNow = new Date(dateString).valueOf();

  // Update the Date accordingly in your test pages
  await page.addInitScript(`{
    // Extend Date constructor to default to fakeNow
    Date = class extends Date {
      constructor(...args) {
        if (args.length === 0) {
          super(${fakeNow});
        } else {
          super(...args);
        }
      }
    }
    // Override Date.now() to start from fakeNow
    Date.now = () => ${fakeNow};
  }`);
};

export const sleep = (ms: number) => {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
};

/**
 * Function that help waiting for something.
 * /!\ Be cautious using this function. The framework Playwright already has
 * a system to wait modification on the UI. So this function should be used
 * only for very particular use cases, it is not the norm.
 *
 * @param conditionPromise A function checking if the condition is verified.
 * @param sleepTimeBetweenLoop Time to wait between each loop in ms.
 * @param loopCount Max loop to do.
 * @param expectToBeTrue The expecting result of the condition.
 */
export const awaitUntilCondition = async (
  conditionPromise: () => Promise<boolean>,
  sleepTimeBetweenLoop = 1000,
  loopCount = 10,
  expectToBeTrue = true,
) => {
  let isConditionOk = await conditionPromise();
  let loopCurrent = 0;
  while (!isConditionOk === expectToBeTrue && loopCurrent < loopCount) {
    await sleep(sleepTimeBetweenLoop);

    isConditionOk = await conditionPromise();
    loopCurrent += 1;
  }
};

export default fakeDate;
