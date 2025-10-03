const MAX_EVENT_LOOP_PROCESSING_TIME = 50;

let nextYield: number | undefined;
export const doYield = async () => {
  if (nextYield !== undefined) {
    if (Date.now() > nextYield) {
      nextYield = undefined;
      await new Promise((resolve) => {
        setTimeout(resolve, 0);
      });
      return true;
    }
  } else {
    nextYield = Date.now() + MAX_EVENT_LOOP_PROCESSING_TIME;
  }
  return false;
};
