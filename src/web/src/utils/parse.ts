export interface Data {
  [key: string]: string | number;
}

export function parseCounterData(data: Result) {
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

  return [x, series];
}

export function objToString(m: any) {
  return JSON.stringify(m);
}
