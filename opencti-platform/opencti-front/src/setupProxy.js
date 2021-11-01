/* eslint-disable */
const { createProxyMiddleware } = require("http-proxy-middleware");

const onError = function (err, req, res) {
  console.log("Something went wrong... Ignoring");
};
const host = process.env.REACT_APP_GRAPHQL_HOST || 'https://graphql.darklight.ai/'

module.exports = function (app) {
  app.use(
    createProxyMiddleware("/graphql", {
      target: host,
      ws: true,
      secure: false,
      onError,
    })
  );
  app.use(
    createProxyMiddleware("/taxii2", {
      target: host,
      onError,
      secure: false,
    })
  );
  app.use(
    createProxyMiddleware("/stream", {
      target: host,
      onError,
      secure: false,
    })
  );
  app.use(
    createProxyMiddleware("/storage", {
      target: host,
      onError,
      secure: false,
    })
  );
  app.use(
    createProxyMiddleware("/auth/**", {
      target: host,
      onError,
      secure: false,
    })
  );
};