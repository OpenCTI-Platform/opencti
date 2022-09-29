const express = require("express");
const { createProxyMiddleware } = require("http-proxy-middleware");
const { readFileSync } = require("node:fs");
const path = require("node:path");
const esbuild = require("esbuild");
const chokidar = require("chokidar");
const compression = require("compression");
const { RelayPlugin } = require("../plugin/esbuild-relay");
const fsExtra = require("fs-extra");

const basePath = "";
const clients = [];
const buildPath = "./builder/dev/build/";
const debounce = (func, timeout = 500) => {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => {
      func.apply(this, args);
    }, timeout);
  };
};

// Start with an initial build
esbuild
  .build({
    logLevel: "info",
    plugins: [RelayPlugin],
    entryPoints: ["src/index.tsx"],
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
    target: ["chrome58"],
    minify: false,
    keepNames: true,
    sourcemap: true,
    sourceRoot: "src",
    outdir: "builder/dev/build",
    incremental: true,
  })
  .then((builder) => {
    // region Copy public files to build
    fsExtra.copySync("./src/static/ext", buildPath + "/static/ext", {
      recursive: true,
      overwrite: true,
    });
    // endregion
    // Listen change for hot recompile
    chokidar
      .watch("src/**/*.{js,jsx,ts,tsx}", {
        awaitWriteFinish: true,
        ignoreInitial: true,
      })
      .on(
        "all",
        debounce(() => {
          const start = new Date().getTime();
          console.log(`[HOT RELOAD] Update of front detected`);
          return builder
            .rebuild()
            .then(() => {
              const time = new Date().getTime() - start;
              console.log(
                `[HOT RELOAD] Rebuild done in ${time} ms, updating frontend`
              );
              clients.forEach((res) => res.write("data: update\n\n"));
              clients.length = 0;
            })
            .catch((error) => {
              console.error(error);
            });
        })
      );
    // Start a dev web server
    const app = express();
    app.set("trust proxy", 1);
    app.get("/dev", (req, res) => {
      return clients.push(
        res.writeHead(200, {
          "Content-Type": "text/event-stream",
          "Cache-Control": "no-cache",
          "Access-Control-Allow-Origin": "*",
          Connection: "keep-alive",
        })
      );
    });
    app.use(
      createProxyMiddleware(basePath + "/stream", {
        target: "http://localhost:4000",
        changeOrigin: true,
        ws: false,
      })
    );
    app.use(
      createProxyMiddleware(basePath + "/storage", {
        target: "http://localhost:4000",
        changeOrigin: true,
        ws: false,
      })
    );
    app.use(
      createProxyMiddleware(basePath + "/taxii2", {
        target: "http://localhost:4000",
        changeOrigin: true,
        ws: false,
      })
    );
    app.use(
      createProxyMiddleware(basePath + "/feeds", {
        target: "http://localhost:4000",
        changeOrigin: true,
        ws: false,
      })
    );
    app.use(
      createProxyMiddleware(basePath + "/graphql", {
        target: "http://localhost:4000",
        changeOrigin: true,
        ws: true,
      })
    );
    app.use(
      createProxyMiddleware(basePath + "/auth/**", {
        target: "http://localhost:4000",
        changeOrigin: true,
        ws: true,
      })
    );
    app.use(compression({}));
    app.use(`/css`, express.static(path.join(__dirname, "./build")));
    app.use(`/js`, express.static(path.join(__dirname, "./build")));
    app.use(
      basePath + `/static`,
      express.static(path.join(__dirname, "./build/static"))
    );
    app.get("*", (req, res) => {
      const data = readFileSync(`${__dirname}/index.html`, "utf8");
      const withOptionValued = data.replace(/%BASE_PATH%/g, basePath);
      res.header(
        "Cache-Control",
        "private, no-cache, no-store, must-revalidate"
      );
      res.header("Expires", "-1");
      res.header("Pragma", "no-cache");
      return res.send(withOptionValued);
    });
    app.listen(3000);
  });
