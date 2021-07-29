import EventSource from 'eventsource';
import { generateBasicAuth } from './testQuery';

// eslint-disable-next-line import/prefer-default-export
export const fetchStreamEvents = (uri, from = '0') => {
  const opts = { headers: { authorization: generateBasicAuth(), 'Last-Event-ID': from } };
  return new Promise((resolve, reject) => {
    let lastEventTime = null;
    const events = [];
    const es = new EventSource(uri, opts);
    const handleEvent = (event) => {
      const { type, data, lastEventId, origin } = event;
      const [time] = lastEventId.split('-');
      const currentTime = parseInt(time, 10);
      lastEventTime = currentTime;
      events.push({ type, data: JSON.parse(data), lastEventId, origin });
      // If no new event for 5 secs, stop the processing
      setTimeout(() => {
        if (lastEventTime === currentTime) {
          resolve(events);
        }
      }, 5000);
    };
    es.addEventListener('update', (event) => handleEvent(event));
    es.addEventListener('create', (event) => handleEvent(event));
    es.addEventListener('merge', (event) => handleEvent(event));
    es.addEventListener('delete', (event) => handleEvent(event));
    es.onerror = (err) => reject(err);
  });
};
