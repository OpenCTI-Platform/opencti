import React, { useState } from 'react';
import { Document, Page } from 'react-pdf';
import Loader from './Loader';

import '../utils/pdfWorker-setup';

interface PdfViewerProps {
  pdf: File;
}

const PdfViewer = ({ pdf }: PdfViewerProps) => {
  const [nbPages, setNbPages] = useState(0);

  return (
    <div style={{
      overflowY: 'scroll',
      height: '100%',
      display: 'flex',
      justifyContent: 'center',
    }}
    >
      <Document
        file={pdf}
        loading={<Loader />}
        onLoadSuccess={({ numPages }) => setNbPages(numPages)}
      >
        {Array.from(new Array(nbPages), (_, i) => (
          <Page
            key={`page_${i + 1}`}
            pageNumber={i + 1}
          />
        ))}
      </Document>
    </div>
  );
};

export default PdfViewer;
