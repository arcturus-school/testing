import { defineStore } from 'pinia';
import { log } from '@utils/log';
import { message } from 'ant-design-vue';
import axios from 'axios';

const req = axios.create({
  baseURL: '/api/v1',
});

req.interceptors.response.use(
  (res) => res.data,
  (err) => {
    message.error(`${err.response.status} ${err.response.statusText}`);

    return Promise.reject(err);
  }
);

interface State {
  labels: { value: string }[];
  label?: string;
}

export const useStore = defineStore('data', {
  state: (): State => {
    return {
      labels: [],
    };
  },
  actions: {
    getLabels() {
      log('start getting labels...');

      req.get('/label/__name__/values').then((res) => {
        const newLabels: { value: string }[] = [];

        for (let i = 0; i < res.data.length; i++) {
          if (res.data[i] !== 'up') {
            newLabels.push({ value: res.data[i] });
          }
        }

        this.labels = newLabels;
      });
    },
  },
});
