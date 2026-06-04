import React, { ReactNode } from 'react';
import { StixCoreObject } from '@components/widgets/WidgetCustomAttributesCard';
import FieldOrEmpty from '../../components/FieldOrEmpty';
import MarkdownDisplay from '../../components/markdownDisplay/MarkdownDisplay';

type AttributeRenderer = (
  data: StixCoreObject,
  t_i18n: (s: string) => string,
  fldt: (s: unknown) => string,
) => ReactNode;

type EntityRenderers = Partial<Record<string, AttributeRenderer>>;

// ─── Campaign
const campaignRenderers: EntityRenderers = {
  objective: (data) => {
    const objective = 'objective' in data
      ? (data as { objective?: string }).objective
      : undefined;
    return (
      <FieldOrEmpty source={objective}>
        <MarkdownDisplay
          content={objective ?? ''}
          remarkGfmPlugin={true}
          commonmark={true}
        />
      </FieldOrEmpty>
    );
  },
  first_seen: (data, t_i18n, fldt) => {
    const firstSeen = 'first_seen' in data ? (data as { first_seen?: unknown }).first_seen : undefined;
    return (
      <FieldOrEmpty source={firstSeen}>
        <span>{fldt(firstSeen)}</span>
      </FieldOrEmpty>
    );
  },
  last_seen: (data, t_i18n, fldt) => {
    const lastSeen = 'last_seen' in data ? (data as { last_seen?: unknown }).last_seen : undefined;
    return (
      <FieldOrEmpty source={lastSeen}>
        <span>{fldt(lastSeen)}</span>
      </FieldOrEmpty>
    );
  },
};

export const entityTypeRenderers: Record<string, EntityRenderers> = {
  Campaign: campaignRenderers,
};
