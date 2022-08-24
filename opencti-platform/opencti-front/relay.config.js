// relay.config.js
module.exports = {
  src: './src',
  language: "typescript",
  schema: ['../opencti-graphql/config/schema/opencti.graphql'],
  exclude: ['**/node_modules/**', '**/__mocks__/**', '**/__generated__/**'],
};
