import { useSyncExternalStore } from 'react';

// Lets components outside the entity header (e.g. workflow transitions in the
// Overview) open the entity's update drawer. EditEntityControlledDial registers
// its opener; the latest registration wins.

type Entry = { open: () => void };

let entries: Entry[] = [];
const listeners = new Set<() => void>();

const notify = () => listeners.forEach((listener) => listener());

export const getEntityEditionOpener = (): (() => void) | null => {
  return entries.length > 0 ? entries[entries.length - 1].open : null;
};

export const registerEntityEditionOpener = (open: () => void): () => void => {
  const entry: Entry = { open };
  entries = [...entries, entry];
  notify();
  return () => {
    if (!entries.includes(entry)) return;
    entries = entries.filter((e) => e !== entry);
    notify();
  };
};

const subscribe = (listener: () => void) => {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
};

export const useEntityEditionOpener = (): (() => void) | null => {
  return useSyncExternalStore(subscribe, getEntityEditionOpener);
};
