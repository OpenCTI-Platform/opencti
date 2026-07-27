import path from 'node:path';
import fs from "node:fs/promises";

const nativeNodeModulesPlugin = () => ({
  name: 'native-node-modules',
  setup: (build) => {
    // If a ".node" file is imported within a module in the "file" namespace, resolve
    // it to an absolute path and put it into the "node-file" virtual namespace.
    build.onResolve({ filter: /\.*$/, namespace: 'file' }, async (args) => {
      if (!args.path.startsWith('.')) {
        return;
      }

      const nodeFile = path.resolve(
        args.resolveDir,
        args.path.endsWith('.node') ? args.path : `${args.path}.node`,
      );

      try {
        await fs.access(nodeFile);
      } catch {
        return;
      }

      return {
        path: path.relative(process.cwd(), nodeFile),
        namespace: 'node-file',
      };
    });

    // Files in the "node-file" virtual namespace call "require()" on the
    // path from esbuild of the ".node" file in the output directory.
    build.onLoad({ filter: /.*/, namespace: 'node-file' }, (args) => {
      return {
        contents: `
            import nodeFilePath from ${JSON.stringify(args.path)};
            module.exports = require(nodeFilePath);
          `,
        resolveDir: path.dirname(args.path),
      };
    });

    // If a ".node" file is imported within a module in the "node-file" namespace, put
    // it in the "file" namespace where esbuild's default loading behavior will handle
    // it. It is already an absolute path since we resolved it to one above.
    build.onResolve(
      { filter: /\.node$/, namespace: 'node-file' },
      (args) => ({
        path: path.join(process.cwd(), args.path),
        namespace: 'file',
      })
    );

    // Tell esbuild's default loading behavior to use the "file" loader for these ".node" files.
    const { initialOptions} = build;
    initialOptions.loader = {
      ...(initialOptions.loader ?? {}),
      '.node': 'file',
    };
  },
});

export default nativeNodeModulesPlugin;
