import { defineStore } from 'pinia';
import { log, warn } from '@utils/log';
import { message } from 'ant-design-vue';
import axios from 'axios';

const req = axios.create({
  baseURL: '/api/v1',
});

req.interceptors.response.use(
  (res) => res.data,
  (err) => {
    const {
      response: { status, statusText },
    } = err;

    message.error(`${status} ${statusText}`);

    return Promise.reject(err);
  }
);

interface MetricsData {}

interface State {
  labels: { value: string }[];
  label: string | null;
  loading: boolean;
  dt: number;
  metricsData: MetricsData;
  start: number | null;
  end: number | null;
  chartType: string;
}

// 这些是 prometheus 自带的指标
const filter = [
  'exposer_request_latencies',
  'exposer_request_latencies_count',
  'exposer_request_latencies_sum',
  'exposer_scrapes_total',
  'exposer_transferred_bytes_total',
  'scrape_duration_seconds',
  'scrape_samples_post_metric_relabeling',
  'scrape_samples_scraped',
  'scrape_series_added',
  'up',
];

export const options = [
  {
    value: 'lines',
    label: '折线图',
  },
  {
    value: 'heatmap',
    label: '热图',
  },
];

export const useStore = defineStore('data', {
  state: (): State => {
    return {
      labels: [],
      label: null,
      loading: false,
      dt: 900, // 15 minutes
      metricsData: {},
      start: null,
      end: null,
      chartType: options[0].value,
    };
  },

  actions: {
    getLabels() {
      log('start to get labels...');

      req.get('/label/__name__/values').then((res) => {
        const newLabels: { value: string }[] = [];

        for (let i = 0; i < res.data.length; i++) {
          if (!filter.includes(res.data[i])) {
            newLabels.push({ value: res.data[i] });
          }
        }

        this.labels = newLabels;
      });
    },

    getMetricData() {
      this.loading = true;

      this.getData().then(() => {
        this.loading = false;
      });
    },

    getData() {
      log(`start to get data of ${this.label}...`);

      return req
        .get(`/query_range`, {
          params: {
            start: this.start,
            end: this.end,
            query: this.label,
          },
        })
        .then((res) => {
          log(`get data of ${this.label}`, res);
        })
        .catch(() => {});
    },

    refreshData() {
      if (this.label !== null) {
        log(`refresh data of ${this.label}...`);

        this.end = new Date().getTime() / 1000;
        this.start = this.end - this.dt;

        this.getData();
      } else {
        warn('unable to refresh due to no metrics selected....');

        message.warn('请先选择指标后再刷新');
      }
    },
  },
});
