type t = 'matrix';

interface Result {
  resultType: t;
  result: {
    metric: {
      __name__: string;
      instance: string;
      job: string;
      le: string;
      [key: string]: string;
    };
    values: [number, string][];
  }[];
}
