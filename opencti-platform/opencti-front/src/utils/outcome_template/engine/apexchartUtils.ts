import { ApexOptions } from 'apexcharts';

const sleep = (delay: number) => new Promise((resolve) => {
  setTimeout(resolve, delay);
});

const chartDataURI = async (chartOptions: ApexOptions) => {
  const options = chartOptions;
  const canvas = document.createElement('canvas');
  canvas.width = 800;
  canvas.height = 400;
  canvas.style.zIndex = '-1';
  canvas.style.position = 'absolute';
  document.body.appendChild(canvas);
  const chart = new ApexCharts(canvas, options);
  await chart.render();
  await sleep(1000); // Wait animations are over
  const dataURI = await chart.dataURI();
  document.body.removeChild(canvas);
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  return dataURI.imgURI;
};

export default chartDataURI;
