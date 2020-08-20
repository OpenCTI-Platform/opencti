const path = require('path');
const { DefinePlugin, HotModuleReplacementPlugin } = require('webpack');
const nodeExternals = require('webpack-node-externals');
const { CleanWebpackPlugin } = require('clean-webpack-plugin');
const StartServerPlugin = require('start-server-webpack-plugin');
const ora = require('ora');

module.exports = (env, argv) => {
  const resolvePath = (dir) => path.resolve(__dirname, dir);
  const addIf = (condition, elements) => (condition ? elements : []);
  const isDev = argv.mode === 'development';
  if (!process.env.NODE_ENV && argv.mode) {
    process.env.NODE_ENV = argv.mode;
  }

  const buildDate = new Date().toISOString();
  return {
    entry: {
      index: [resolvePath('src/index'), ...addIf(isDev, [`${require.resolve('webpack/hot/poll')}?1000`])],
    },
    resolve: {
      extensions: ['.wasm', '.mjs', '.js', '.json', '.graphql'],
    },
    externals: [nodeExternals({ allowlist: [/^webpack/] })],
    watch: isDev,
    target: 'node',
    output: {
      path: resolvePath('build'),
      libraryTarget: 'commonjs2',
    },
    devtool: isDev ? 'eval-source-map' : '',
    optimization: { noEmitOnErrors: true },
    stats: !isDev && {
      children: false,
      entrypoints: false,
      modules: false,
    },
    node: {
      __dirname: true,
    },
    module: {
      rules: [
        {
          use: 'babel-loader',
          test: /\.js$/,
          include: resolvePath('src'),
        },
        {
          use: 'graphql-tag/loader',
          test: /\.graphql$/,
          include: resolvePath('config'),
        },
      ],
    },
    plugins: [
      new DefinePlugin({
        OPENCTI_BUILD_DATE: JSON.stringify(buildDate),
      }),
      new CleanWebpackPlugin(),
      ...addIf(isDev, [
        new HotModuleReplacementPlugin(),
        new StartServerPlugin(),
        {
          apply: (compiler) => {
            const interactive = process.stdout.isTTY;
            const spinner = ora();
            const spinStart = (msg) => (interactive ? spinner.start(msg) : console.log(msg));
            const spinSucceed = (msg) => (interactive ? spinner.succeed(msg) : console.log(msg));
            const spinWarn = (msg) => (interactive ? spinner.warn(msg) : console.log(msg));
            const spinFail = (msg) => (interactive ? spinner.fail(msg) : console.log(msg));

            compiler.hooks.invalid.tap('CompilationReport', () => {
              spinStart('Compiling...');
            });

            compiler.hooks.done.tap('CompilationReport', (stats) => {
              // remove compiler stack traces
              stats.compilation.errors.forEach((e) => {
                e.message = e.error.message;
              });
              const statsData = stats.toJson({ all: false, warnings: true, errors: true });

              const hasWarnings = statsData.warnings.length > 0;
              const hasErrors = statsData.errors.length > 0;

              if (hasErrors) {
                // Compilation failed
                spinFail('Failed to compile.');
                console.log([...statsData.errors, ...statsData.warnings].join('\n\n'));
                console.log();
              } else if (hasWarnings) {
                // Compilation succeed with warning
                spinWarn('Compiled with warnings.');
                console.log(statsData.warnings.join('\n\n'));
                console.log();
              } else {
                spinSucceed('Compiled successfully!');
              }
            });
          },
        },
      ]),
    ],
  };
};
