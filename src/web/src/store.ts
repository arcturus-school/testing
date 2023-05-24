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

    log(err);

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
            if (
              !res.data[i].endsWith('sum') &&
              !res.data[i].endsWith('count')
            ) {
              newLabels.push({ value: res.data[i] });
            }
          }
        }

        this.labels = newLabels;
      });
    },

    getMetricData() {
      this.loading = true;

      if (this.start !== null && this.end !== null) {
        // 有时间范围时
        this.end = new Date().getTime() / 1000;
        this.start = this.end - this.dt;

        this.getData(this.start, this.end).then(() => {
          this.loading = false;
        });
      } else {
        // 有 dt 时
        const end = new Date().getTime() / 1000;
        const start = end - this.dt;

        this.getData(start, end).then(() => {
          this.loading = false;
        });
      }
    },

    getData(start: number, end: number) {
      log(`start to get data of ${this.label}...`);

      const dt = end - start;

      return req
        .get(`/query_range`, {
          params: {
            start: start,
            end: end,
            query: this.label,
            // 按照 1800 秒内 257 个数据点获取数据
            step: Math.round(dt / 1800) * 7,
          },
        })
        .then((res) => {
          log(`data of ${this.label}`);
          log(res);
        })
        .catch(() => {});
    },

    refreshData() {
      if (this.label !== null) {
        if (this.dt !== 0) {
          log(`refresh data of ${this.label}...`);

          const end = new Date().getTime() / 1000;
          const start = end - this.dt;

          this.getData(start, end);
        }
      } else {
        warn('unable to refresh due to no metrics selected....');

        message.warn('请先选择指标后再刷新');
      }
    },
  },
});
