import React, { useState } from 'react';
import { Document, Page, pdfjs } from 'react-pdf';
import 'react-pdf/dist/esm/Page/TextLayer.css';
import 'react-pdf/dist/esm/Page/AnnotationLayer.css';
import Loader from './Loader';
import { APP_BASE_PATH } from '../relay/environment';

if (!pdfjs.GlobalWorkerOptions.workerSrc) {
  pdfjs.GlobalWorkerOptions.workerSrc = `${APP_BASE_PATH}/static/ext/pdf.worker.mjs`;
}

interface PdfViewerProps {
  pdf: File
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
