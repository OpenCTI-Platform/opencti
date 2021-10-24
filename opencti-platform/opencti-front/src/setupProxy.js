/* eslint-disable */
const { createProxyMiddleware } = require("http-proxy-middleware");

const onError = function (err, req, res) {
  console.log("Something went wrong... Ignoring");
};

module.exports = function (app) {
  app.use(
    createProxyMiddleware("/graphql", {
      target: "http://157.245.20.236:5000",
      ws: true,
      onError,
    })
  );
  app.use(
    createProxyMiddleware("/taxii2", {
      target: "http://157.245.20.236:5000",
      onError,
    })
  );
  app.use(
    createProxyMiddleware("/stream", {
      target: "http://157.245.20.236:5000",
      onError,
    })
  );
  app.use(
    createProxyMiddleware("/storage", {
      target: "http://157.245.20.236:5000",
      onError,
    })
  );
  app.use(
    createProxyMiddleware("/auth/**", {
      target: "http://157.245.20.236:5000",
      onError,
    })
  );
};
