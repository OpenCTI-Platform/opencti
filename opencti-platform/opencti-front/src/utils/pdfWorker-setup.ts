import { pdfjs } from 'react-pdf';
// eslint-disable-next-line import/no-extraneous-dependencies
import pdfWorkerUrl from 'pdfjs-dist/legacy/build/pdf.worker.min.mjs?url';

pdfjs.GlobalWorkerOptions.workerSrc = pdfWorkerUrl;
