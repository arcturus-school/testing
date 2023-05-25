// 防抖函数
export function debounce(func: Function, wait: number) {
  let timer: NodeJS.Timeout;

  return function (this: unknown, ...args: any[]) {
    const that = this;

    clearTimeout(timer);

    timer = setTimeout(() => {
      func.apply(that, args);
    }, wait);
  };
}
