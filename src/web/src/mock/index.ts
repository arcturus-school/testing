import Mock from 'mockjs';
import { log } from '@utils/log';

Mock.setup({ timeout: '1000' });

Mock.mock(/\/api\/v1\/label\/__name__\/values/, {
  status: 'success',
  data: [
    'bio_latency_histogram_bucket',
    'bio_latency_histogram_count',
    'bio_latency_histogram_sum',
    'exposer_request_latencies',
    'exposer_request_latencies_count',
    'exposer_request_latencies_sum',
    'exposer_scrapes_total',
    'exposer_transferred_bytes_total',
    'scrape_duration_seconds',
    'scrape_samples_post_metric_relabeling',
    'scrape_samples_scraped',
    'scrape_series_added',
    'tcp_connect_latency_bucket',
    'tcp_connect_latency_count',
    'tcp_connect_latency_sum',
    'tcp_retrans_counter',
    'tcp_rtt_histogram_bucket',
    'tcp_rtt_histogram_count',
    'tcp_rtt_histogram_sum',
    'up',
  ],
});

Mock.mock(/\/api\/v1\/query_range.*bucket.*/, {
  status: 'success',
  data: {
    resultType: 'matrix',
    'result|28': [
      {
        metric: {
          __name__: 'bio_latency_histogram_bucket',
          dev: '1795',
          instance: 'exporter:8089',
          job: 'ecli',
          'le|+1': [
            ...new Array(27)
              .fill(null)
              .map((_, idx) => Math.pow(2, idx).toString()),
            '+Inf',
          ],
          op: 'read',
        },
        values: function () {
          const res: [number, string][] = [];
          const now = new Date().getTime() / 1000;

          for (let i = 256; i >= 0; i--) {
            res.push([now - 7 * i, Math.round(Math.random() * 2).toString()]);
          }

          return res;
        },
      },
    ],
  },
});

Mock.mock(/\/api\/v1\/query_range.*counter/, {
  status: 'success',
  data: {
    resultType: 'matrix',
    'result|80': [
      {
        metric: {
          __name__: 'tcp_retrans_counter',
          daddr: '@ip',
          dport: () => Math.round(Math.random() * 65535).toString(),
          instance: 'exporter:8089',
          job: 'ecli',
          protocol: 'IPv4',
          saddr: '@ip',
          sport: () => Math.round(Math.random() * 65535).toString(),
        },
        values: function () {
          const res: [number, string][] = [];
          const now = new Date().getTime() / 1000;

          for (let i = 256; i >= 0; i--) {
            res.push([now - 7 * i, '1']);
          }

          return res;
        },
      },
    ],
  },
});

log('mock loading complete...');
