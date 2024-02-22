const express = require("express");
const { createProxyMiddleware } = require("http-proxy-middleware");
const { readFileSync } = require("node:fs");
const path = require("node:path");
const esbuild = require("esbuild");
const compression = require("compression");
const { RelayPlugin } = require("../plugin/esbuild-relay");
const fsExtra = require("fs-extra");

const basePath = "";
const clients = [];
const buildPath = "./builder/dev/build/";

const middleware = (target, ws = false) => createProxyMiddleware(basePath + target, {
  target: process.env.BACK_END_URL ?? 'http://localhost:4000',
  changeOrigin: true,
  ws,
})

// Start with an initial build
esbuild.context({
  logLevel: "info",
  plugins: [RelayPlugin],
  entryPoints: ["src/front.tsx"],
  publicPath: "/",
  bundle: true,
  banner: {
    js: ' (() => new EventSource("http://localhost:3000/dev").onmessage = () => location.reload())();',
  },
  loader: {
    ".js": "jsx",
    ".svg": "file",
    ".png": "file",
    ".woff": "dataurl",
    ".woff2": "dataurl",
    ".ttf": "dataurl",
    ".eot": "dataurl",
  },
  assetNames: "[dir]/[name]-[hash]",
  entryNames: "static/[ext]/[name]-[hash]",
  target: ["chrome58"],
  minify: true,
  keepNames: false,
  sourcemap: false,
  sourceRoot: "src",
  outdir: "builder/dev/build",
}).then(async (builder) => {
  // region Copy public files to build
  fsExtra.copySync("./src/static/ext", buildPath + "/static/ext", {
    recursive: true,
    overwrite: true,
  });
  // endregion
  // region Start a dev web server
  const app = express();
  app.get("/dev", (req, res) => {
    return clients.push(
      res.writeHead(200, {
        "Content-Type": "text/event-stream",
        "Access-Control-Allow-Origin": "*",
        Connection: "keep-alive",
      })
    );
  });
  app.set("trust proxy", 1);
  app.use(compression({}));
  app.use(middleware("/health"));
  app.use(middleware("/logout"));
  app.use(middleware("/stream"));
  app.use(middleware("/storage"));
  app.use(middleware("/taxii2"));
  app.use(middleware("/feeds"));
  app.use(middleware("/graphql", true));
  app.use(middleware("/auth/**"));
  app.use(middleware("/static/flags/**"));
  app.use(basePath + `/static`, express.static(path.join(__dirname, "./build/static")));
  app.use(`/css`, express.static(path.join(__dirname, "./build")));
  app.use(`/js`, express.static(path.join(__dirname, "./build")));
  app.get("*", (req, res) => {
    const data = readFileSync(`${__dirname}/index.html`, "utf8");
    const withOptionValued = data
      .replace(/%BASE_PATH%/g, basePath)
      .replace(/%APP_TITLE%/g, "OpenCTI Dev")
      .replace(/%APP_DESCRIPTION%/g, "OpenCTI Development platform")
      .replace(/%APP_FAVICON%/g, `${basePath}/static/ext/favicon.png`)
      .replace(/%APP_MANIFEST%/g, `${basePath}/static/ext/manifest.json`);
    return res.send(withOptionValued);
  });
  app.listen(3000);
  // endregion
});
