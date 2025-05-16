import { DynamicBackground } from 'pdfmake/interfaces';

const pdfBackground = (linearGradiant: string[] | undefined) => {
  const background: DynamicBackground = (currentPage, pageSize) => {
    return {
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
    };
  };
  return background;
};

export default pdfBackground;
