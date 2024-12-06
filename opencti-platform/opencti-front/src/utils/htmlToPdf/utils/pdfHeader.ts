import { DynamicContent } from 'pdfmake/interfaces';

const pdfHeader: DynamicContent = (currentPage, pageCount, pageSize) => {
  if (currentPage === 1 || currentPage === pageCount) return [];
  return [{
    canvas:
      [{
        type: 'rect',
        x: 0,
        y: 0,
        w: pageSize.width,
        h: 12,
        linearGradient: ['#00020C', '#001BDA'],
      }],
  }];
};

export default pdfHeader;
