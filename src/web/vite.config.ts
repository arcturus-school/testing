import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';
import { resolve } from 'path';

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [vue()],
  resolve: {
    alias: {
      '@src': resolve(__dirname, 'src'),
      '@mock': resolve(__dirname, 'mock'),
    },
  },
  server: {
    proxy: {
      '/api/v1': {
        target: 'http://prometheus:9090',
        // changeOrigin: true,
      },
    },
  },
});
