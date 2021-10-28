/* eslint-disable */
const { createProxyMiddleware } = require("http-proxy-middleware");

const onError = function (err, req, res) {
  console.log("Something went wrong... Ignoring");
};
const host = process.env.REACT_APP_GRAPHQL_HOST || 'http://localhost:4000'

module.exports = function (app) {
  app.use(
    createProxyMiddleware("/graphql", {
      target: host,
      ws: true,
      onError,
    })
  );
  app.use(
    createProxyMiddleware("/taxii2", {
      target: host,
      onError,
    })
  );
  app.use(
    createProxyMiddleware("/stream", {
      target: host,
      onError,
    })
  );
  app.use(
    createProxyMiddleware("/storage", {
      target: host,
      onError,
    })
  );
  app.use(
    createProxyMiddleware("/auth/**", {
      target: host,
      onError,
    })
  );
};