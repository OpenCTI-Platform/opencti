/* eslint-disable */
const { createProxyMiddleware } = require("http-proxy-middleware");

const onError = function (err, req, res) {
  console.log("Something went wrong... Ignoring");
};

module.exports = function (app) {
  app.use(
    createProxyMiddleware("/graphql", {
      target: "https://graphql.darklight.ai/",
      ws: true,
      secure: false,
      onError,
    })
  );
  app.use(
    createProxyMiddleware("/taxii2", {
      target: "https://graphql.darklight.ai/",
      secure: false,
      onError,
    })
  );
  app.use(
    createProxyMiddleware("/stream", {
      target: "https://graphql.darklight.ai/",
      secure: false,
      onError,
    })
  );
  app.use(
    createProxyMiddleware("/storage", {
      target: "https://graphql.darklight.ai/",
      secure: false,
      onError,
    })
  );
  app.use(
    createProxyMiddleware("/auth/**", {
      target: "https://graphql.darklight.ai/",
      secure: false,
      onError,
    })
  );
};
