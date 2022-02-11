import path from 'node:path';
import glob from 'glob';
import { DefinePlugin, HotModuleReplacementPlugin } from 'webpack';
import nodeExternals from 'webpack-node-externals';
import TerserPlugin from 'terser-webpack-plugin';
import { CleanWebpackPlugin } from 'clean-webpack-plugin';
import { RunScriptWebpackPlugin } from 'run-script-webpack-plugin';

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
      'script-clean-relations': [resolvePath('script/script-clean-relations')],
    },
    resolve: {
      extensions: ['.wasm', '.mjs', '.js', '.json', '.graphql', '.ts'],
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
          use: 'ts-loader',
          test: /\.ts$/,
          include: resolvePath('src'),
        },
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
