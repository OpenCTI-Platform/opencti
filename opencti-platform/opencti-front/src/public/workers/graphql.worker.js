// Re-export GraphQL language worker for Monaco.
// This wrapper exists so that Vite's worker bundling treats this as a project file
// (fully controlled bundling) rather than a bare node_modules reference.
// eslint-disable-next-line import/no-extraneous-dependencies
import 'monaco-graphql/esm/graphql.worker.js';
