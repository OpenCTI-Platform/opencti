/* eslint-disable */
const { createProxyMiddleware } = require('http-proxy-middleware');

const onError = function(err, req, res) {
  console.log('Something went wrong... Ignoring');
};

module.exports = function(app) {
  app.use(createProxyMiddleware("/graphql", { target: "http://localhost:4000", ws: true, onError }));
  app.use(createProxyMiddleware("/storage", { target: "http://localhost:4000", onError }));
  app.use(createProxyMiddleware("/auth/**", { target: "http://localhost:4000", onError }));
};
