const esbuild = require("esbuild");
const { RelayPlugin } = require("../plugin/esbuild-relay");
const fsExtra = require("fs-extra");
const fs = require("fs");

const buildPath = "./builder/prod/build/";
esbuild
  .build({
    logLevel: "info",
    plugins: [RelayPlugin],
    entryPoints: ["src/index.tsx"],
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
    assetNames: "static/media/[name]-[hash]",
    entryNames: "static/[ext]/opencti-[hash]",
    target: ["chrome58"],
    minify: true,
    keepNames: false,
    sourcemap: false,
    sourceRoot: "src",
    sourcesContent: false,
    outdir: "builder/prod/build",
    incremental: false,
  })
  .then(() => {
    // Copy file
    fsExtra.copySync("./builder/public/", buildPath, {
      recursive: true,
      overwrite: true,
    });
    // Generate index.html
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
        <meta http-equiv="Content-Type" content="text/html; charset=utf-8"/>
        <meta http-equiv="X-UA-Compatible" content="IE=edge"/>
        <script>window.BASE_PATH = "%BASE_PATH%"</script>
        <meta name="viewport" content="width=device-width,initial-scale=1">
        <title></title>
        <link id="favicon" rel="shortcut icon" href="">
        ${jsImport}
        ${cssImport}
        </head>
        <body>
            <noscript>You need to enable JavaScript to run this app.</noscript>
            <div id="root"></div>
        </body>
    </html>`;
    fs.writeFileSync(buildPath + "index.html", indexHtml);
  });
