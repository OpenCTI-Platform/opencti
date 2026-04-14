// Re-export Monaco base editor worker.
// This wrapper exists so that Vite's worker bundling treats this as a project file
// (fully controlled bundling) rather than a bare node_modules reference.

import 'monaco-editor/esm/vs/editor/editor.worker.js';
