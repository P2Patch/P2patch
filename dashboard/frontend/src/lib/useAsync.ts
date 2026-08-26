import { useEffect, useState } from "react";

export interface AsyncState<T> {
  data: T | null;
  error: string | null;
  loading: boolean;
}

/** Minimal fetch-on-mount hook keyed by `deps`. */
export function useAsync<T>(fn: () => Promise<T>, deps: unknown[]): AsyncState<T> {
  const [state, setState] = useState<AsyncState<T>>({ data: null, error: null, loading: true });

  useEffect(() => {
    let alive = true;
    setState({ data: null, error: null, loading: true });
    fn()
      .then((data) => alive && setState({ data, error: null, loading: false }))
      .catch((err) => alive && setState({ data: null, error: String(err.message ?? err), loading: false }));
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  return state;
}
