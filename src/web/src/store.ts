import { defineStore } from 'pinia';
import { log } from '@utils/log';
import { message } from 'ant-design-vue';
import { updateCounterData } from '@utils/draw';
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

interface State {
  labels: { value: string }[];
  label: string;
  loading: boolean;
  dt: number;
  metricsData: Result | null;
  start: number | null;
  end: number | null;
  chartType: 'bucket' | 'counter' | '';
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

export const useStore = defineStore('data', {
  state: (): State => {
    return {
      labels: [],
      label: '',
      loading: false,
      dt: 900, // 15 minutes
      metricsData: null,
      start: null,
      end: null,
      chartType: '',
    };
  },

  actions: {
    getLabels() {
      log('start to get labels...');

      req.get('/label/__name__/values').then((res) => {
        const newLabels: { value: string }[] = [];

        for (let i = 0; i < res.data.length; i++) {
          const label = res.data[i];

          if (!filter.includes(label)) {
            if (!label.endsWith('sum') && !label.endsWith('count')) {
              newLabels.push({ value: label });
            }
          }
        }

        this.labels = newLabels;
      });
    },

    getMetricData(label: string) {
      this.loading = true;

      if (this.start !== null && this.end !== null) {
        return this.getData(label, this.start, this.end).then(() => {
          this.loading = false;
        });
      } else {
        const end = new Date().getTime() / 1000;
        const start = end - this.dt;

        return this.getData(label, start, end).then(() => {
          this.loading = false;
        });
      }
    },

    updateChartData() {
      log('Update chart data...');

      if (this.chartType === 'bucket') {
      } else if (this.chartType === 'counter') {
        updateCounterData(this.metricsData!);
      }
    },

    getDateByRange() {
      if (this.label !== '') {
        return this.getData(this.label, this.start!, this.end!).then(() => {
          this.updateChartData();
        });
      }
    },

    getDataByDt() {
      if (this.label !== '') {
        const end = new Date().getTime() / 1000;
        const start = end - this.dt;

        return this.getData(this.label, start, end).then(() => {
          this.updateChartData();
        });
      }
    },

    getData(label: string, start: number, end: number) {
      log(`Start to get data of ${this.label}...`);

      const dt = end - start;

      return req
        .get(`/query_range`, {
          params: {
            start: start,
            end: end,
            query: label,
            // 按照 1800 秒内 257 个数据点获取数据
            step: Math.round(dt / 1800) * 7,
          },
        })
        .then((res) => {
          log(`Obtain data of ${label}:`);
          log(res);

          this.metricsData = res.data;
        })
        .catch(() => {});
    },

    refreshData() {
      if (this.label === '') {
        message.warn('请先选择指标后再刷新');
        return;
      }

      if (this.dt !== 0) {
        log(`Refresh data of [${this.label}]`);

        const end = new Date().getTime() / 1000;
        const start = end - this.dt;

        this.getData(this.label, start, end).then(() => {
          this.updateChartData();
        });
      }
    },
  },
});
