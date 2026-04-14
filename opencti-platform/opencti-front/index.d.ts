declare module '*.png';
declare module '*.jpg';
declare module '*.svg';
declare module 'react-rectangle-selection';

// Vite Web Worker imports (https://vite.dev/guide/features#import-with-query-suffixes)
declare module '*?worker' {
  const workerConstructor: {
    new (): Worker;
  };
  export default workerConstructor;
}

// Monaco Editor environment (used by setupMonacoWorkers.ts)
interface Window {
  MonacoEnvironment?: {
    getWorker(workerId: string, label: string): Worker;
  };
}
