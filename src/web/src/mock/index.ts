import Mock from 'mockjs';
import { log } from '@utils/log';

// mock data
import COUNTER from '@mock/retrans.json';
import BUCKET from '@mock/bucket.json';

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

Mock.mock(/\/api\/v1\/query_range.*bucket.*/, BUCKET);

Mock.mock(/\/api\/v1\/query_range.*counter/, COUNTER);

log('mock loading complete...');
