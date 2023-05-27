function getX(data: Result) {
  let idx = 0,
    len = 0;

  for (let i = 0; i < data.result.length; i++) {
    if (data.result[i].values.length > len) {
      len = data.result[i].values.length;
      idx = i;
    }
  }

  // x-axis
  return data.result[idx].values.map((v) => v[0] * 1000);
}

export function parseCounterData(data: Result) {
  const x = getX(data);

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

function toNumber(n: string) {
  return n === '+Inf' ? Infinity : Number(n);
}

type r = [number[], number[], number, any[]];

export function parseBucketData(data: Result): r {
  const x = getX(data);

  x.shift();

  const cat: { [key: string]: any[] } = {};

  // 收集某一数据在不同 le 下的数据
  for (let i = 0; i < data.result.length; i++) {
    const { le, __name__, ...k } = data.result[i].metric;
    const key = Object.values(k).join('_');

    if (key in cat) {
      cat[key].push(data.result[i]);
    } else {
      cat[key] = [data.result[i]];
    }
  }

  // 根据 le 进行排序
  for (const c in cat) {
    cat[c].sort((a, b) => {
      const le1 = toNumber(a.metric.le);
      const le2 = toNumber(b.metric.le);

      return le1 - le2;
    });
  }

  let max = 0;
  for (const c in cat) {
    const items = cat[c];

    for (let i = 0; i < items[0].values.length; i++) {
      items[0].values[i][1] = Number(items[0].values[i][1]);
      items[0].values[i].push(items[0].values[i][1]);
    }

    for (let i = 1; i < items.length; i++) {
      const item = items[i].values;

      for (let j = 0; j < item.length; j++) {
        item[j][1] = Number(item[j][1]);
        item[j].push(item[j][1] - items[i - 1].values[j][1]);
      }
    }

    for (let i = 0; i < items.length; i++) {
      const item = items[i].values;

      for (let j = 1; j < item.length; j++) {
        item[j].push(item[j][2] - item[j - 1][2]);

        if (max < item[j][3]) {
          max = item[j][3];
        }
      }

      item.shift();
    }
  }

  const t = cat[Object.keys(cat)[0]];
  const y = t.map((v) => toNumber(v.metric.le));

  const r: Record<number, any> = {};

  for (const c in cat) {
    const item = cat[c];

    for (let i = 0; i < item.length; i++) {
      for (let j = 0; j < item[i].values.length; j++) {
        // 某个时间点
        if (item[i].values[j][0] in r) {
          const t = r[item[i].values[j][0]];
          const le = toNumber(item[i].metric.le);

          if (le in t) {
            t[le] += item[i].values[j][3];
          } else {
            t[le] = item[i].values[j][3];
          }
        } else {
          const le = toNumber(item[i].metric.le);

          r[item[i].values[j][0]] = {};
          r[item[i].values[j][0]][le] = item[i].values[j][3];
        }
      }
    }
  }

  const res = [];

  for (let t in r) {
    for (let v in r[t]) {
      if (r[t][v] !== 0) {
        v = v === '+Inf' ? String(Infinity) : v;

        res.push([String(Number(t) * 1000), v, r[t][v]]);
      }
    }
  }

  return [x, y, max, res];
}
