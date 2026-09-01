import { defineConfig } from 'vite';

export default defineConfig({
  root: './',
  base: '/',
  resolve: {
    extensions: ['.ts', '.js']
  },
  build: {
    target: 'modules',
    outDir: '../public/live2d-build',
    emptyOutDir: true,
    sourcemap: false,
    rollupOptions: {
      output: {
        entryFileNames: 'live2d.js',
        chunkFileNames: 'chunks/[name].js',
        assetFileNames: 'assets/[name][extname]'
      }
    }
  }
});
