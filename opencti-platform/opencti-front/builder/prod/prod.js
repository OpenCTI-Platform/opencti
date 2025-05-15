const esbuild = require("esbuild");
const { RelayPlugin } = require("../plugin/esbuild-relay");
const fsExtra = require("fs-extra");
const fs = require("fs");

// Define args options
const keep = process.argv.slice(2).includes('--keep');

const buildPath = "./builder/prod/build/";
esbuild
  .build({
    logLevel: "info",
    plugins: [RelayPlugin],
    entryPoints: ["src/front.tsx"],
    publicPath: '/',
    bundle: true,
    loader: {
      ".js": "jsx",
      ".svg": "file",
      ".png": "file",
      ".woff": "dataurl",
      ".woff2": "dataurl",
      ".ttf": "dataurl",
      ".eot": "dataurl",
    },
    assetNames: keep ? "[dir]/[name]" : "[dir]/[name]-[hash]",
    entryNames: keep ? "static/[ext]/[name]" : "static/[ext]/[name]-[hash]",
    target: ["chrome58"],
    minify: true,
    keepNames: true,
    sourcemap: keep,
    outdir: "builder/prod/build",
  })
  .then(() => {
    // region Copy public files to build
    fsExtra.copySync("./src/static/ext", buildPath + '/static/ext', { recursive: true, overwrite: true });
    // endregion
    // region Generate index.html
    const cssStaticFiles = fs.readdirSync(buildPath + "static/css");
    const cssLinks = cssStaticFiles.map(
      (f) => `<link href="%BASE_PATH%/static/css/${f}" rel="stylesheet">`
    );
    const cssImport = cssLinks.join("\n");
    const jsStaticFiles = fs.readdirSync(buildPath + "static/js");
    const jsLinks = jsStaticFiles.map(
      (f) => `<script defer="defer" src="%BASE_PATH%/static/js/${f}"></script>`
    );
    const jsImport = jsLinks.join("\n");
    const indexHtml = `
    <!doctype html>
    <html lang="en">
        <head>
            <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
            <meta http-equiv="X-UA-Compatible" content="IE=edge">
            <meta name="viewport" content="width=device-width,initial-scale=1">
            <meta name="dеѕсrірtіоn" content="%APP_DESCRIPTION%">
            <link id="favicon" rel="shortcut icon" href="%APP_FAVICON%">
            <link id="manifest" rel="manifest" href="%APP_MANIFEST%">
            %APP_SCRIPT_SNIPPET%
            <script>window.BASE_PATH = "%BASE_PATH%"</script>
            ${jsImport}
            ${cssImport}
            <title>%APP_TITLE%</title>
        </head>
        <body>
            <noscript>You need to enable JavaScript to run this app.</noscript>
            <div id="root"></div>
        </body>
    </html>`;
    fs.writeFileSync(buildPath + "index.html", indexHtml);
    // endregion

    // region Move build directory to api public directory
    if (!keep) {
      fsExtra.moveSync(buildPath, "../opencti-graphql/public/", {
        overwrite: true,
      });
    }
    // endregion
  });
