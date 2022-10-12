// relay.config.js
module.exports = {
  src: './src',
  language: "typescript",
  schema: './relay.schema.graphql',
  excludes: ['**/node_modules/**', '**/__mocks__/**', '**/__generated__/**'],
};
