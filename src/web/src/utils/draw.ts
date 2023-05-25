import { Chart } from '@antv/g2';
import { log } from '@utils/log';
import { Renderer } from '@antv/g-svg';
import dayjs from 'dayjs';

let chart: Chart | null = null;

const svgRenderer = new Renderer();

export function drawHeatMap(id: string, metricsData: Result) {
  log('render heatmap chart...');

  chart = new Chart({
    container: id,
    theme: 'classic',
    autoFit: true,
    renderer: svgRenderer,
    marginBottom: 20,
  });

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

export function drawLines() {
  // if (chart !== null) {
  //   log('render lines chart...');
  //   chart
  //     .line()
  //     .data({
  //       type: 'fetch',
  //       value: 'https://assets.antv.antgroup.com/g2/indices.json',
  //     })
  //     .transform({ type: 'normalizeY', basis: 'first', groupBy: 'color' })
  //     .encode('x', (d: any) => new Date(d.Date))
  //     .encode('y', 'Close')
  //     .encode('color', 'Symbol')
  //     .scale('y', { type: 'log' })
  //     .axis('y', { title: '↑ Change in price (%)' })
  //     .label({
  //       text: 'Symbol',
  //       selector: 'last',
  //       style: {
  //         fontSize: 10,
  //       },
  //     })
  //     .tooltip({ channel: 'y', valueFormatter: '.1f' });
  //   chart.render();
  // }
}
