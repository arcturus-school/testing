import { Chart } from '@antv/g2';
import { log } from '@utils/log';
import { Renderer } from '@antv/g-svg';
import { Data, objToString, parseCounterData } from '@utils/parse';
import dayjs from 'dayjs';

let chart: Chart | null = null;

const svgRenderer = new Renderer();

function createChart(id: string) {
  return new Chart({
    container: id,
    theme: 'classic',
    autoFit: true,
    renderer: svgRenderer,
    marginBottom: 20,
  });
}

export function drawHeatMap(id: string, metricsData: Result) {
  log('render heatmap chart...');

  chart = createChart(id);

  chart
    .rect()
    .data({
      type: 'custom',
      callback: () => {
        return metricsData.result.flatMap((r) => {
          return r.values.map((v) => {
            return {
              le: r.metric.le === '+Inf' ? Infinity : Number(r.metric.le),
              count: Number(v[1]),
              date: v[0] * 1000,
            };
          });
        });
      },
    })
    .encode('x', 'date')
    .encode('y', 'le')
    .encode('color', 'count')
    .transform({
      type: 'binX',
      color: 'sum',
    })
    .style('inset', 0.5)
    .scale('color', { palette: 'ylGnBu' })
    .animate('enter', { type: 'fadeIn' })
    .axis('y', {
      title: false,
    })
    .axis('x', {
      title: '时间',
      titlePosition: 'bottom',
      label: {
        autoHide: true,
      },
      labelFormatter: (e: number) => dayjs(e).format('MM-DD HH:mm'),
    })
    .tooltip({
      title: (_, idx, __, column) => {
        const start = dayjs(column.x.value[idx!]).format('YYYY-MM-DD HH:mm:ss');
        const end = dayjs(column.x1.value[idx!]).format('YYYY-MM-DD HH:mm:ss');

        return `${start} ~ ${end}`;
      },
      items: [
        { channel: 'color', name: 'count' },
        (_, idx, __, column) => ({
          name: 'le',
          value: `${column.y1.value[idx!]}, ${column.y.value[idx!]}`,
        }),
      ],
    });

  chart.render();
}

export function drawCounter(id: string, metricsData: Result) {
  chart = createChart(id);

  chart
    .line()
    .data(parseCounterData(metricsData))
    .encode('x', 'date')
    .encode('y', 'count')
    .encode('color', (d: Data) => objToString(d.metric))
    .axis('y', { title: false })
    .scale('y', { domainMin: 0 })
    .axis('x', {
      title: '时间',
      titlePosition: 'bottom',
      label: {
        autoHide: true,
      },
      labelFormatter: (e: number) => dayjs(e).format('YYYY-MM-DD HH:mm'),
    })
    .tooltip({
      title: (_, idx, __, column) => {
        return dayjs(column.x.value[idx!]).format('YYYY-MM-DD HH:mm:ss');
      },
    })
    .legend('color', false);

  chart.render();
}

export function updateCounterData(metricsData: Result) {
  if (chart !== null) {
    chart.changeData(parseCounterData(metricsData));
  }
}
