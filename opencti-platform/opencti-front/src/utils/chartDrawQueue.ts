// Charts measured together (a dashboard mounting its widgets) would all be drawn in one long task:
// the first one is drawn at once, the next ones one per task, so that the page responds between them
const pendingChartDraws: (() => void)[] = [];
let isChartDrawTaskBusy = false;
const drawNextChart = () => {
  const draw = pendingChartDraws.shift();
  if (draw) {
    draw();
    setTimeout(drawNextChart, 0);
  } else {
    isChartDrawTaskBusy = false;
  }
};

/**
 * Runs the first draw of a chart, at once or in a later task when another chart was just drawn.
 * Returns a function cancelling the draw if it did not run yet.
 */
export const scheduleChartDraw = (draw: () => void) => {
  if (!isChartDrawTaskBusy) {
    isChartDrawTaskBusy = true;
    draw();
    setTimeout(drawNextChart, 0);
    return () => {};
  }
  const pendingDraw = () => draw();
  pendingChartDraws.push(pendingDraw);
  return () => {
    const index = pendingChartDraws.indexOf(pendingDraw);
    if (index >= 0) pendingChartDraws.splice(index, 1);
  };
};
