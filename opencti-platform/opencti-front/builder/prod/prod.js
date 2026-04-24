const esbuild = require("esbuild");
const { cp, rename, rm, readdir, writeFile } = require("node:fs/promises")
const { RelayPlugin } = require("../plugin/esbuild-relay");

// Define args options
const keep = process.argv.slice(2).includes('--keep');

const buildPath = "./builder/prod/build";

(async () => {
  // Build Monaco web workers as separate bundles (required for GraphiQL schema completion)
  await esbuild.build({
      logLevel: "info",
      entryPoints: [
        "src/public/workers/editor.worker.ts",
        "src/public/workers/json.worker.ts",
        "src/public/workers/graphql.worker.ts",
      ],
      bundle: true,
      format: "iife",
      minify: true,
      target: ["chrome58"],
      outdir: `${buildPath}/static/workers`,
      entryNames: "[name]",
      loader: { ".js": "jsx" },
      // prettier/parser-graphql does not exist in prettier v3 (replaced by
      // prettier/plugins/graphql). Marking prettier as external avoids a build
      // error; doFormat will fail gracefully at runtime but autocompletion is
      // unaffected because it uses doComplete / doValidation only.
      external: ["prettier", "prettier/standalone", "prettier/parser-graphql"],
    });

  await esbuild.build({
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
      define: {
        // Allows setupMonacoWorkers.ts to detect prod vs dev at build time.
        // The DEV branch (new Worker(new URL(..., import.meta.url))) is dead code
        // eliminated by esbuild so import.meta.url is never processed in IIFE mode.
        'import.meta.env': JSON.stringify({ DEV: false, PROD: true, MODE: 'production' }),
      },
      assetNames: keep ? "[dir]/[name]" : "[dir]/[name]-[hash]",
      entryNames: keep ? "static/[ext]/[name]" : "static/[ext]/[name]-[hash]",
      target: ["chrome58"],
      minify: true,
      mainFields: ["browser", "module", "main"],
      keepNames: true,
      sourcemap: keep,
      outdir: "builder/prod/build",
    });
  // Copy public files to build
  await cp("./src/static/ext",  `${buildPath}/static/ext`, { recursive: true, overwrite: true });

  // Generate index.html
  const cssImport = (await readdir(`${buildPath}/static/css`))
    .map((f) => `<link href="%BASE_PATH%/static/css/${f}" rel="stylesheet">`)
    .join("\n");

  const jsImport = (await readdir(`${buildPath}/static/js`))
    .map((f) => `<script defer="defer" src="%BASE_PATH%/static/js/${f}"></script>`)
    .join("\n");

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
  await writeFile(`${buildPath}/index.html`, indexHtml);

  // Move build directory to api public directory
  if (!keep) {
    await rm("../opencti-graphql/public/", {recursive: true, force: true});
    await rename(buildPath, "../opencti-graphql/public/");
  }
})();
