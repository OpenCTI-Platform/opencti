/* eslint-disable @typescript-eslint/no-explicit-any */
import { useEffect } from 'react';

type useBusCallback = (a: any) => void;
let subscribers: [channel: string, callback: useBusCallback][] = [];

const subscribe = (channel: string, callback: useBusCallback) => {
  if (!channel || !callback) {
    return undefined;
  }
  subscribers = [
    ...subscribers,
    [channel, callback],
  ];

  return () => {
    subscribers = subscribers.filter((subscriber) => subscriber[1] !== callback);
  };
};

export const dispatch = (channel: string, event?: any) => {
  subscribers.filter(([filter]) => filter === channel)
    .forEach(([_, callback]) => {
      callback(event);
    });
};

const useBus = (channel: string, callback: useBusCallback, deps: any[] = []) => {
  useEffect(() => subscribe(channel, callback), deps);
  return dispatch;
};

export default useBus;
