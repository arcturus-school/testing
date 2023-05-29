import { EChartsOption, ECharts, init } from 'echarts';
import { debounce } from '@utils/tools';
import { parseBucketData, parseCounterData } from '@utils/parse';
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

const xAxisOptions: any = {
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
    formatter: (v: string) => dayjs(Number(v)).format('YYYY-MM-DD HH:mm'),
  },
  splitLine: {
    show: true,
    lineStyle: {
      color: '#f0f0f0',
    },
  },
};

const yAxisOptions: any = {
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
};

export function initChart(ctx: HTMLDivElement) {
  chart = init(ctx, undefined, { renderer: 'svg' });

  window.addEventListener('resize', resize);
}

export function drawHeatMap(data: Result, query: any) {
  const [x, y, max, res] = parseBucketData(data);

  // 补齐剩下的坐标
  const s = query.start * 1000,
    e = query.end * 1000,
    step = query.step * 1000;

  while (s < x[0]) {
    x.unshift(x[0] - step);
  }

  while (true) {
    if (x[x.length - 1] > e) {
      break;
    }

    x.push(x[x.length - 1] + step);
  }

  const option: EChartsOption = {
    tooltip: {
      position: 'top',
      formatter: (p: any) => {
        let res = `<div style="background: ${p.color}; width: 12px; height: 12px; border-radius: 6px; display: inline-block; margin-right: 6px"></div>`;

        const d = `<span style="font-weight: bold;"><% date %></span><br/>`;

        res += d.replace(
          '<% date %>',
          dayjs(Number(p.name)).format('YYYY-MM-DD HH:mm:ss')
        );

        res += `count: ${p.data[2]}<br/>bucket: ${p.data[1]}`;

        return res;
      },
    },
    grid: {
      left: 0,
      right: 0,
      top: 40,
      bottom: 30,
      containLabel: true,
    },
    xAxis: {
      ...xAxisOptions,
      data: x,
    },
    yAxis: {
      ...yAxisOptions,
      type: 'category',
      data: y,
      splitArea: {
        show: true,
      },
    },
    visualMap: {
      min: 0,
      max: max,
      type: 'continuous',
      show: true,
      hoverLink: false,
      orient: 'horizontal',
      right: 0,
      top: 0,
      text: [String(max), '0'],
    },
    series: [
      {
        type: 'heatmap',
        data: res,
        emphasis: {
          itemStyle: {
            shadowBlur: 10,
            shadowColor: 'rgba(0, 0, 0, 0.5)',
          },
        },
      },
    ],
  };

  chart!.setOption(option);
}

export function drawCounter(data: Result, query: any) {
  const [x, series] = parseCounterData(data);

  // 补齐剩下的坐标
  const s = query.start * 1000,
    e = query.end * 1000,
    step = query.step * 1000;

  while (s < x[0]) {
    x.unshift(x[0] - step);
  }

  while (true) {
    if (x[x.length - 1] > e) {
      break;
    }

    x.push(x[x.length - 1] + step);
  }

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
      ...xAxisOptions,
      data: x,
    },
    yAxis: yAxisOptions,
    series,
  };

  chart!.setOption(option);
}

export function updateCounterData(data: Result, query: any) {
  const [x, series] = parseCounterData(data);

  const s = query.start * 1000,
    e = query.end * 1000,
    step = query.step * 1000;

  while (s < x[0]) {
    x.unshift(x[0] - step);
  }

  while (true) {
    if (x[x.length - 1] > e) {
      break;
    }

    x.push(x[x.length - 1] + step);
  }

  chart!.setOption({
    xAxis: {
      data: x,
    },
    series,
  });
}

export function updateHeatmapData(data: Result, query: any) {
  const [x, y, max, res] = parseBucketData(data);

  const s = query.start * 1000,
    e = query.end * 1000,
    step = query.step * 1000;

  while (s < x[0]) {
    x.unshift(x[0] - step);
  }

  while (true) {
    if (x[x.length - 1] > e) {
      break;
    }

    x.push(x[x.length - 1] + step);
  }

  chart!.setOption({
    xAxis: {
      data: x,
    },
    yAxis: {
      data: y,
    },
    visualMap: {
      max: max,
      text: [String(max), '0'],
    },
    series: [
      {
        type: 'heatmap',
        data: res,
        emphasis: {
          itemStyle: {
            shadowBlur: 10,
            shadowColor: 'rgba(0, 0, 0, 0.5)',
          },
        },
      },
    ],
  });
}

export function destroy() {
  chart!.dispose();

  window.removeEventListener('resize', resize);
}

export function clear() {
  if (chart !== null) {
    chart.clear();
  }
}
