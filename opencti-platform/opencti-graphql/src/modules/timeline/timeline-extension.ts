import { cleanObject } from '../../database/stix-converter-utils';
import type { StixTimelineExtension, StoreTimelineExchange } from './timeline-types';

/**
 * Build the timeline STIX extension from the analyst contributions denormalized on a container.
 * Returns undefined when there is nothing to carry, so that containers without contributions
 * keep exactly the same STIX representation as before the timeline existed.
 */
export const buildStixTimelineExtension = (exchange: StoreTimelineExchange | null | undefined): StixTimelineExtension | undefined => {
  if (!exchange) return undefined;
  const events = exchange.events ?? [];
  const annotations = exchange.annotations ?? [];
  if (events.length === 0 && annotations.length === 0) return undefined;
  return {
    extension_type: 'property-extension',
    events: events.map((event) => cleanObject({ ...event })),
    annotations: annotations.map((annotation) => cleanObject({ ...annotation })),
  };
};
