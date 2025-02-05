import { DynamicBackground } from 'pdfmake/interfaces';

const pdfBackground: DynamicBackground = (currentPage, pageSize) => {
  return {
    canvas: currentPage > 1
      ? []
      : [{
        type: 'rect',
        x: 0,
        y: 0,
        w: pageSize.width,
        h: pageSize.height,
        linearGradient: ['#00020C', '#001BDA'],
      }],
  };
};

export default pdfBackground;
