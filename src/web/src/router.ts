import EChart from '@pages/e-chart.vue';
import EEmpty from '@pages/e-empty.vue';
import { createRouter, createWebHistory } from 'vue-router';

const routes = [
  {
    path: '/:metrics',
    component: EChart,
  },
  {
    path: '/',
    component: EEmpty,
  },
];

export const router = createRouter({
  history: createWebHistory(),
  routes,
});
