type t = 'matrix';

interface Result {
  resultType: t;
  result: {
    metrics: {
      __name__: string;
      instance: string;
      job: string;
      le: string;
      [key: string]: string;
    };
    values: [number, string][];
  }[];
}
