/* eslint-disable */
const proxy = require("http-proxy-middleware");

const onError = function(err, req, res) {
  console.log('Something went wrong... Ignoring');
};

module.exports = function(app) {
  app.use(proxy("/graphql", { target: "http://opencti.limeo.org:4000", ws: true, onError }));
  app.use(proxy("/storage", { target: "http://opencti.limeo.org:4000", onError }));
  app.use(proxy("/auth/**", { target: "http://opencti.limeo.org:4000", onError }));
};
