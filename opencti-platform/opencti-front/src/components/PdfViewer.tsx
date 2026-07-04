import React, { useState } from 'react';
import { Document, Page, pdfjs } from 'react-pdf';
import Loader from './Loader';

pdfjs.GlobalWorkerOptions.workerSrc = new URL('pdfjs-dist/build/pdf.worker.min.mjs', import.meta.url).toString();

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
