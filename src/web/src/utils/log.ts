export const log = (msg: any, ...options: any[]) => {
  if (import.meta.env.DEV) {
    console.log(msg, ...options);
  }
};

export const warn = (msg: any, ...options: any[]) => {
  if (import.meta.env.DEV) {
    console.warn(msg, ...options);
  }
};
