import { pdfjs } from 'react-pdf';
// Explicit asset import: the production build did not resolve `new URL('pdfjs-dist/…', import.meta.url)`
// and pointed the worker at this chunk, so every PDF failed with "Setting up fake worker failed".
import workerSrc from 'pdfjs-dist/build/pdf.worker.min.mjs?url';

pdfjs.GlobalWorkerOptions.workerSrc = workerSrc;
