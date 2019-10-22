/* config-overrides.js */

module.exports = function override(config) {
  config.module.rules.push(
    {
      test: /\.mjs$/,
      include: /node_modules\/react-relay-network-modern/,
      type: 'javascript/auto',
    },
  );
  config.resolve.extensions.push('.mjs');
  return config;
};
