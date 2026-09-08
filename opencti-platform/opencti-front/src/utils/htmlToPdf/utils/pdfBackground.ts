import { DynamicBackground } from 'pdfmake/interfaces';

const pdfBackground = (
  linearGradiant: string[] | undefined,
  options?: { hasCoverPage?: boolean },
): DynamicBackground => {
  const hasCoverPage = options?.hasCoverPage ?? true;
  return (currentPage, pageSize) => ({
    canvas: !hasCoverPage || currentPage > 1
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
