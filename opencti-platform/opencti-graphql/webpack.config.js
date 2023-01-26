const path = require('path');
const glob = require('glob');
const { DefinePlugin, HotModuleReplacementPlugin } = require('webpack');
const nodeExternals = require('webpack-node-externals');
const TerserPlugin = require('terser-webpack-plugin');
const { CleanWebpackPlugin } = require('clean-webpack-plugin');
const { RunScriptWebpackPlugin } = require('run-script-webpack-plugin');

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
      index: [
        resolvePath('src/index'),
        ...glob.sync('./src/rules/**/*.js'),
        ...addIf(isDev, [`${require.resolve('webpack/hot/poll')}?1000`]),
      ],
    },
    resolve: {
      extensions: ['.wasm', '.mjs', '.js', '.json', '.graphql'],
    },
    externals: [
      nodeExternals({
        additionalModuleDirs: [path.resolve(__dirname, '../node_modules')],
        allowlist: [/^webpack/],
      }),
    ],
    watch: isDev,
    target: 'node',
    output: {
      path: resolvePath('build'),
      devtoolModuleFilenameTemplate: isDev ? '[absolute-resource-path]' : '[resource-path]',
    },
    devtool: 'inline-source-map',
    optimization: {
      emitOnErrors: false,
      minimize: !isDev,
      minimizer: [
        new TerserPlugin({
          extractComments: false,
          terserOptions: {
            mangle: false,
          },
        }),
      ],
    },
    stats: {
      children: false,
      entrypoints: false,
      modules: false,
      logging: true,
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
      ...addIf(isDev, [new HotModuleReplacementPlugin(), new RunScriptWebpackPlugin()]),
    ],
  };
};
