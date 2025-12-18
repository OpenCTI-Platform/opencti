import { displayEntityTypeForTranslation } from './String';
import { isNotEmptyField } from './utils';
import { useFormatter } from '../components/i18n';

export const useGenerateAuditMessage = <T extends {
  entity_type?: string | null;
  event_type: string;
  event_scope?: string | null;
  user?: { name: string } | null;
  context_data?: { entity_name?: string | null; entity_type?: string | null; message: string } | null;
}>(data: T) => {
  const { t_i18n } = useFormatter();
  const isHistoryUpdate = data.entity_type === 'History'
    && (data.event_type === 'update' || data.event_scope === 'update')
    && isNotEmptyField(data.context_data?.entity_name);
  const entityType = data.context_data?.entity_type ?? '';
  return `\`${data.user?.name}\` ${data.context_data?.message} ${
    isHistoryUpdate
      ? `for \`${data.context_data?.entity_name}\` (${t_i18n(displayEntityTypeForTranslation(entityType))})`
      : ''
  }`;
};
