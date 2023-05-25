export interface Data {
  [key: string]: string | number;
}

export function parseCounterData(data: Result): Data[] {
  return data.result.flatMap((e) => {
    const m: any = Object.assign({}, e.metric);

    // 去掉一些无所谓的数据
    delete m.__name__;
    delete m.job;
    delete m.instance;

    return e.values.map((v) => {
      return {
        metric: m,
        date: v[0] * 1000,
        count: Number(v[1]),
      };
    });
  });
}

export function objToString(m: any) {
  return JSON.stringify(m);
}
