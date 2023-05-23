export const log = (msg: any, ...options: any[]) => {
  if (import.meta.env.DEV) {
    console.log(msg, ...options);
  }
};
