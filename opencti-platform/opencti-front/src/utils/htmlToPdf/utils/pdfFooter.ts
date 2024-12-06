import { DynamicContent } from 'pdfmake/interfaces';

const pdfFooter = (markingNames: string[]) => {
  const footer: DynamicContent = (currentPage, pageCount) => {
    if (currentPage === pageCount) return [];
    return {
      margin: [20, 4, 20, 0],
      style: [currentPage === 1 ? 'colorWhite' : 'colorLight'],
      columns: [
        {
          text: markingNames.join(', '),
          alignment: 'left',
        },
        {
          text: `${currentPage} / ${pageCount - 1}`,
          alignment: 'right',
        },
      ],
    };
  };
  return footer;
};

export default pdfFooter;
