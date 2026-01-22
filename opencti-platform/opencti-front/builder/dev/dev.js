const express = require("express");
const { createProxyMiddleware } = require("http-proxy-middleware");
const { cp, readFile } = require("node:fs/promises")
const path = require("node:path");
const esbuild = require("esbuild");
const chokidar = require("chokidar");
const compression = require("compression");
const { RelayPlugin } = require("../plugin/esbuild-relay");

const basePath = "";
const clients = [];
const buildPath = "./builder/dev/build/";
const frontPort = process.env.FRONT_END_PORT ?? 3000;
const debounce = (func, timeout = 500) => {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => {
      func.apply(this, args);
    }, timeout);
  };
};
const middleware = (target, ws = false) => createProxyMiddleware({
  target: process.env.BACK_END_URL ?? "http://localhost:4000",
  pathFilter: basePath + target,
  changeOrigin: true,
  ws,
});

(async () => {
  // Start with an initial build
  const builder = await esbuild.context({
      logLevel: "info",
      plugins: [RelayPlugin],
      entryPoints: ["src/front.tsx"],
      publicPath: "/",
      bundle: true,
      banner: {
        js: ` (() => new EventSource("http://localhost:${frontPort}/dev").onmessage = () => location.reload())();`,
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
      minify: true,
      keepNames: true,
      sourcemap: true,
      outdir: "builder/dev/build",
    })
  await builder.rebuild();

  // Copy public files to build
  await cp("./src/static/ext", `${buildPath}/static/ext`, {
    recursive: true,
    force: true,
  });

  // Listen change for hot recompile
  if (!process.env.E2E_TEST) {
    chokidar.watch("src/**/*.{js,jsx,ts,tsx}", {
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
  }

  // Start a dev web server
  const app = express();
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
  app.set("trust proxy", 1);
  app.use(compression({}));
  app.use(middleware("/health"));
  app.use(middleware("/logout"));
  app.use(middleware("/stream"));
  app.use(middleware("/storage"));
  app.use(middleware("/chatbot"));
  app.use(middleware("/taxii2"));
  app.use(middleware("/feeds"));
  app.use(middleware("/graphql", true));
  app.use(middleware("/auth/**"));
  app.use(middleware("/static/flags/**"));
  app.use(basePath + `/static`, express.static(path.join(__dirname, "./build/static")));
  app.use(`/css`, express.static(path.join(__dirname, "./build")));
  app.use(`/js`, express.static(path.join(__dirname, "./build")));
  app.get("*any", async (req, res) => {
    const data = await readFile(`${__dirname}/index.html`, "utf8");
    const withOptionValued = data
      .replace(/%BASE_PATH%/g, basePath)
      .replace(/%APP_SCRIPT_SNIPPET%/g,  '')
      .replace(/%APP_TITLE%/g, "OpenCTI Dev")
      .replace(/%APP_DESCRIPTION%/g, "OpenCTI Development platform")
      .replace(/%APP_FAVICON%/g, `${basePath}/static/ext/favicon.png`)
      .replace(/%APP_MANIFEST%/g, `${basePath}/static/ext/manifest.json`);
    if (!process.env.E2E_TEST) {
      res.header(
        "Cache-Control",
        "private, no-cache, no-store, must-revalidate"
      );
      res.header("Expires", "-1");
      res.header("Pragma", "no-cache");
    }
    return res.send(withOptionValued);
  });
  app.listen(frontPort);
})();
