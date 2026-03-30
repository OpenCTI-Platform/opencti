import { isNotEmptyField } from './utils';
import useEntityTranslation from './hooks/useEntityTranslation';

export const useTranslateHistoryMessage = () => {
  const { translateEntityType } = useEntityTranslation();
  return (message: string, entityType?: string | null) => {
    if (!entityType) return message;
    const translated = translateEntityType(entityType);
    if (translated === entityType) return message;
    return message.replace(entityType, translated);
  };
};

export const useGenerateAuditMessage = <T extends {
  entity_type?: string | null;
  event_type: string;
  event_scope?: string | null;
  user?: { name: string } | null;
  context_data?: { entity_name?: string | null; entity_type?: string | null; message: string } | null;
}>(data: T) => {
  const { translateEntityType } = useEntityTranslation();
  const isHistoryUpdate = data.entity_type === 'History'
    && (data.event_type === 'update' || data.event_scope === 'update')
    && isNotEmptyField(data.context_data?.entity_name);
  const entityType = data.context_data?.entity_type ?? '';
  const entityTypeLabel = translateEntityType(entityType);
  const rawMessage = data.context_data?.message ?? '';
  const translatedMessage = entityType && entityTypeLabel !== entityType
    ? rawMessage.replace(entityType, entityTypeLabel)
    : rawMessage;
  return `${translatedMessage} ${
    isHistoryUpdate
      ? `for \`${data.context_data?.entity_name}\` (${entityTypeLabel})`
      : ''
  }`;
};
