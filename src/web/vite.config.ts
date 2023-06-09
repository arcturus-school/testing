import { defineConfig } from 'vite';
import { resolve } from 'path';
import { AntDesignVueResolver } from 'unplugin-vue-components/resolvers';
import Components from 'unplugin-vue-components/vite';
import vue from '@vitejs/plugin-vue';

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [
    vue(),
    Components({
      resolvers: [AntDesignVueResolver()],
    }),
  ],
  resolve: {
    alias: {
      '@src': resolve(__dirname, 'src'),
      '@mock': resolve(__dirname, 'src/mock'),
      '@components': resolve(__dirname, 'src/components'),
      '@utils': resolve(__dirname, 'src/utils'),
      '@pages': resolve(__dirname, 'src/pages'),
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
