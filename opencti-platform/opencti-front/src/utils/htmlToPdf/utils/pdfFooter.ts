import { DynamicContent } from 'pdfmake/interfaces';

const pdfFooter = (
  markingNames: string[],
  options?: { hasCoverPage?: boolean; hasBackPage?: boolean },
) => {
  const hasCoverPage = options?.hasCoverPage ?? true;
  const hasBackPage = options?.hasBackPage ?? true;
  const footer: DynamicContent = (currentPage, pageCount) => {
    if (hasBackPage && currentPage === pageCount) return [];
    const displayedPageCount = pageCount - (hasBackPage ? 1 : 0);
    return {
      margin: [20, 4, 20, 0],
      style: [hasCoverPage && currentPage === 1 ? 'colorWhite' : 'colorLight'],
      columns: [
        {
          text: markingNames.join(', '),
          alignment: 'left',
        },
        {
          text: `${currentPage} / ${displayedPageCount}`,
          alignment: 'right',
        },
      ],
    };
  };
  return footer;
};

export default pdfFooter;
