import { buildStixObject } from '../../database/stix-2-1-converter';
import { cleanObject } from '../../database/stix-converter-utils';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import { isEmptyField } from '../../database/utils';
import type { StixTimelineEvent, StixTimelineSettings, StoreEntityTimelineEvent, StoreEntityTimelineSettings } from './timeline-types';

const toStixDate = (date: string | Date | null | undefined): string | undefined => {
  if (isEmptyField(date)) return undefined;
  return new Date(date as string).toISOString();
};

export const convertTimelineEventToStix = (instance: StoreEntityTimelineEvent): StixTimelineEvent => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    name: instance.name,
    title: instance.name,
    description: instance.description,
    container_ref: instance.container_id,
    event_time: toStixDate(instance.event_time) as string,
    event_end_time: toStixDate(instance.event_end_time),
    precision: instance.time_precision,
    lane: instance.lane,
    kind: instance.kind,
    source: instance.event_source,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      }),
    },
  };
};

export const convertTimelineSettingsToStix = (instance: StoreEntityTimelineSettings): StixTimelineSettings => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    name: `Timeline settings of ${instance.container_id}`,
    container_ref: instance.container_id,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      }),
    },
  };
};
