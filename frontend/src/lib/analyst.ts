import { createContext, useContext, useEffect, useState } from "react";

const KEY = "phishcatch.analyst";

export function useAnalyst(): [string, (value: string) => void] {
  const [analyst, setAnalyst] = useState("local-analyst");
  useEffect(() => {
    const stored = window.localStorage.getItem(KEY);
    if (stored) setAnalyst(stored);
  }, []);
  function update(value: string) {
    setAnalyst(value);
    window.localStorage.setItem(KEY, value);
  }
  return [analyst, update];
}

export const AnalystContext = createContext("local-analyst");

export function useAnalystId(): string {
  return useContext(AnalystContext);
}

export function analystId(value: string): string {
  const cleaned = value.trim();
  return cleaned || "local-analyst";
}
