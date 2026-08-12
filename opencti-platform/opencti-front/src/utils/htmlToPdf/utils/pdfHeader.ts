import { DynamicContent } from 'pdfmake/interfaces';

const pdfHeader = (
  linearGradiant: string[] | undefined,
  options?: { hasCoverPage?: boolean; hasBackPage?: boolean },
): DynamicContent => (currentPage, pageCount, pageSize) => {
  const hasCoverPage = options?.hasCoverPage ?? true;
  const hasBackPage = options?.hasBackPage ?? true;
  if ((hasCoverPage && currentPage === 1) || (hasBackPage && currentPage === pageCount)) return [];
  return [{
    canvas: [{
      type: 'rect',
      x: 0,
      y: 0,
      w: pageSize.width,
      h: 12,
      linearGradient: linearGradiant,
    }],
  }];
};

export default pdfHeader;
