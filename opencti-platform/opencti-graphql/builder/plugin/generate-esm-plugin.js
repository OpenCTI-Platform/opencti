export const generateEsmPlugin = () => ({
  name: 'generate-esm',
  setup: ({ initialOptions }) => {
    initialOptions.format = 'esm';
    initialOptions.outExtension = {
      ...(initialOptions.outExtension ?? {}),
      '.js': '.mjs',
    };
    initialOptions.banner = {
      ...(initialOptions.banner ?? {}),
      // see https://github.com/evanw/esbuild/issues/1921
      js: `
const { require, __filename, __dirname } = await (async () => {
  const { createRequire } = await import('node:module');
  const { fileURLToPath } = await import('node:url');
  const { dirname } = await import('node:path');
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = dirname(__filename);
  return {
    require: createRequire(import.meta.url),
    __filename,
    __dirname,
  };
})();
`,
    };
  },
});
