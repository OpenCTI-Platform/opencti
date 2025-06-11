import { DynamicBackground } from 'pdfmake/interfaces';

const pdfBackground = (linearGradiant: string[] | undefined): DynamicBackground => {
  return (currentPage, pageSize) => ({
    canvas: currentPage > 1
      ? []
      : [{
        type: 'rect',
        x: 0,
        y: 0,
        w: pageSize.width,
        h: pageSize.height,
        linearGradient: linearGradiant,
      }],
  });
};

export default pdfBackground;
