// No 'vite' import: this config lives outside any node_modules tree, so
// defineConfig would not resolve. A plain object is equivalent.
import react from '<OPENCTI_FRONT>/node_modules/@vitejs/plugin-react/dist/index.js';
const NM = '<OPENCTI_FRONT>/node_modules';
export default {
  plugins: [react()],
  server: { port: 4300, strictPort: true, fs: { allow: ['/'] } },
  resolve: {
    alias: {
      'react-dom/client': NM + '/react-dom/client.js',
      'react/jsx-runtime': NM + '/react/jsx-runtime.js',
      'react/jsx-dev-runtime': NM + '/react/jsx-dev-runtime.js',
      'react-dom': NM + '/react-dom/index.js',
      react: NM + '/react/index.js',
      '@radix-ui/react-select': NM + '/@radix-ui/react-select/dist/index.mjs',
      '@filigran/design-system': NM + '/@filigran/design-system/packages/filigran-design-system/dist/index.mjs',
    },
    dedupe: ['react', 'react-dom'],
  },
};
