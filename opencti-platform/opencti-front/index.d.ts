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

// import.meta.env — provided by Vite at runtime and replaced via esbuild `define` in prod.
// Declaring it here avoids TypeScript errors in files that read import.meta.env.DEV.
interface ImportMeta {
  readonly env?: {
    readonly DEV: boolean;
    readonly PROD: boolean;
    readonly MODE: string;
  };
}

