import { EChartsOption, ECharts, init } from 'echarts';
import { debounce } from '@utils/tools';
import dayjs from 'dayjs';

let chart: ECharts | null = null;

const resize = debounce(() => {
  chart?.resize({
    animation: {
      duration: 300,
      easing: 'linear',
    },
  });
}, 200);

export function initChart(ctx: HTMLDivElement) {
  chart = init(ctx, undefined, { renderer: 'svg' });

  window.addEventListener('resize', resize);
}

export function drawHeatMap(data: Result) {}

export function drawCounter(data: Result) {
  let idx = 0,
    len = 0;

  for (let i = 0; i < data.result.length; i++) {
    if (data.result[i].values.length > len) {
      len = data.result[i].values.length;
      idx = i;
    }
  }

  // x-axis
  const x = data.result[idx].values.map((v) => v[0] * 1000);

  // series data
  const series: any = data.result.map((v) => {
    const m: any = Object.assign({}, v.metric);

    // 去掉一些无所谓的数据
    delete m.__name__;
    delete m.job;
    delete m.instance;

    return {
      type: 'line',
      // smooth: true,
      showSymbol: false,
      data: v.values.map((e) => ({
        ...m,
        value: Number(e[1]),
      })),
    };
  });

  const option: EChartsOption = {
    tooltip: {
      show: true,
      trigger: 'item',
      axisPointer: {
        type: 'cross',
        label: {
          show: false,
        },
      },
      formatter: (p: any) => {
        let res = `<div style="background: ${p.color}; width: 12px; height: 12px; border-radius: 6px; display: inline-block; margin-right: 6px"></div>`;

        const d = `<span style="font-weight: bold;"><% date %></span><br/>`;

        res += d.replace(
          '<% date %>',
          dayjs(Number(p.name)).format('YYYY-MM-DD HH:mm:ss')
        );

        for (let o in p.data) {
          if (o === 'value') {
            res += `count: ${p.data[o as keyof typeof p]}<br/>`;
          } else {
            res += `${o}: ${p.data[o as keyof typeof p]}<br/>`;
          }
        }

        return res;
      },
    },
    grid: {
      left: 0,
      right: 0,
      top: 20,
      bottom: 30,
      containLabel: true,
    },
    xAxis: {
      type: 'category',
      name: '时间',
      nameLocation: 'middle',
      boundaryGap: true,
      nameTextStyle: {
        padding: [20, 0, 0, 0],
        color: '#262626',
        fontFamily: '',
      },
      axisLine: {
        show: true,
        lineStyle: {
          color: '#f0f0f0',
        },
      },
      axisLabel: {
        show: true,
        color: '#262626',
        fontFamily: '',
        showMinLabel: false,
        formatter: (v) => dayjs(Number(v)).format('YYYY-MM-DD HH:mm'),
      },
      splitLine: {
        show: true,
        lineStyle: {
          color: '#f0f0f0',
        },
      },
      data: x,
    },
    yAxis: {
      show: true,
      type: 'value',
      axisLine: {
        show: true,
        lineStyle: {
          color: '#f0f0f0',
        },
      },
      splitLine: {
        show: true,
        lineStyle: {
          color: '#f0f0f0',
        },
      },
      axisLabel: {
        show: true,
        color: '#262626',
        fontFamily: '',
      },
    },
    series,
  };

  chart!.setOption(option);
}

export function updateCounterData(data: Result) {}

export function destroy() {
  chart!.dispose();

  window.removeEventListener('resize', resize);
}
