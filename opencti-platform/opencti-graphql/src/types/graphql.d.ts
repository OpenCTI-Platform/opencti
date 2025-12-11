declare module '*.graphql' {
  // oxlint-disable-next-line import/extensions
  import { DocumentNode } from 'graphql/index.js';

  const Schema: DocumentNode;

  export = Schema;
}
