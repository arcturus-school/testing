import { createApp } from 'vue';
import { createPinia } from 'pinia';
import { log } from '@utils/log';
import { router } from '@src/router';
import app from '@src/app.vue';

import 'ant-design-vue/es/message/style/css';
import '@src/global.scss';

if (import.meta.env.DEV) {
  log('import mock...');
  await import('@mock/index');
}

createApp(app).use(createPinia()).use(router).mount('#app');
