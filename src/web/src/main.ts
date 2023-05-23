import { createApp } from 'vue';
import app from '@src/app.vue';

if (import.meta.env.DEV) {
  import('@mock/index');
}

createApp(app).mount('#app');
