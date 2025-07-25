import React from 'react';
import MarkdownDisplay from '../../../components/MarkdownDisplay';
import { displayEntityTypeForTranslation } from '../../../utils/String';
import { isNotEmptyField } from '../../../utils/utils';
import { useFormatter } from '../../../components/i18n';

export interface PirLog {
  readonly context_data: {
    readonly entity_id: string | null | undefined;
    readonly entity_name: string | null | undefined;
    readonly entity_type: string | null | undefined;
    readonly message: string;
  } | null | undefined;
  readonly entity_type: string | null | undefined;
  readonly event_scope: string | null | undefined;
  readonly user: {
    readonly name: string;
  } | null | undefined;
}

interface PirHistoryMessageProps {
  log: PirLog
  pirName: string
}

const PirHistoryMessage = ({ log, pirName }: PirHistoryMessageProps) => {
  const { t_i18n } = useFormatter();
  const { context_data, entity_type, event_scope, user } = log;

  const getHistoryMessage = () => {
    const message = context_data?.message ?? '';
    const entityType = t_i18n(displayEntityTypeForTranslation(context_data?.entity_type ?? ''));

    if (message.match(/adds .+ in `In PIR`/)) {
      return t_i18n('', {
        id: '{entityType} `{entityName}` added to `{pirName}`',
        values: {
          entityType,
          entityName: context_data?.entity_name,
          pirName,
        },
      });
    }
    if (message.match(/removes .+ in `In PIR`/)) {
      return t_i18n('', {
        id: '{entityType} `{entityName}` removed from `{pirName}`',
        values: {
          entityType,
          entityName: context_data?.entity_name,
          pirName,
        },
      });
    }

    const isUpdate = entity_type === 'History'
      && event_scope === 'update'
      && isNotEmptyField(context_data?.entity_name);

    // Default message
    return `\`${user?.name}\` ${message} ${isUpdate ? `for \`${context_data?.entity_name}\` (${entityType})` : ''}`;
  };

  return (
    <MarkdownDisplay
      commonmark
      remarkGfmPlugin
      content={getHistoryMessage()}
    />
  );
};

export default PirHistoryMessage;
