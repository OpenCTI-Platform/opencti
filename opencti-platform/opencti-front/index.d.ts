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

// Type declarations for Monaco/monaco-graphql ESM worker entry points.
// These subpath modules do not ship .d.ts files; the any-typed stubs below
// satisfy TypeScript while esbuild bundles the actual JS implementations.
declare module 'monaco-editor/esm/vs/editor/editor.worker' {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  export function initialize(foreignModuleFactory: (ctx: any, createData: any) => any): void;
}
declare module 'monaco-graphql/esm/GraphQLWorker' {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  export class GraphQLWorker { constructor(ctx: any, createData: any); }
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

