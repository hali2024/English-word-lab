import { defineConfig } from 'vite';
import path from 'path';

export default defineConfig({
  root: './',
  base: '/',
  resolve: {
    extensions: ['.ts', '.js'],
    alias: {
      '@framework': path.resolve(__dirname, '../live2d-framework/src'),
    },
  },
  build: {
    target: 'modules',
    outDir: './dist',
    assetsDir: 'assets',
    emptyOutDir: true,
  },
});
