declare module '*.graphql' {
  import { DocumentNode } from 'graphql/index.js';

  const Schema: DocumentNode;

  export = Schema;
}
