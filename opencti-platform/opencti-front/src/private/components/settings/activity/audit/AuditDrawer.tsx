import Drawer from '@components/common/drawer/Drawer';
import { Stack } from '@mui/material';
import { FunctionComponent, Suspense } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { Link } from 'react-router-dom';
import Alert from '../../../../../components/Alert';
import Loader from '../../../../../components/Loader';
import Label from '../../../../../components/common/label/Label';
import ChangesTable, { Change } from '../../../../../components/common/table/ChangesTable';
import { useFormatter } from '../../../../../components/i18n';
import { useGenerateAuditMessage } from '../../../../../utils/history';
import useAuth from '../../../../../utils/hooks/useAuth';
import { AuditDrawerQuery } from './__generated__/AuditDrawerQuery.graphql';

interface AuditDrawerProps {
  open: boolean;
  onClose: () => void;
  logId: string;
}

const auditDrawerQuery = graphql`
  query AuditDrawerQuery($id: ID!, $tz: String, $locale: String, $unit_system: String) {
    audit(id: $id) {
      id
      entity_type
      event_type
      event_scope
      event_status
      timestamp
      context_uri
      user {
        id
        name
      }
      raw_data
      context_data(tz: $tz, locale: $locale, unit_system: $unit_system) {
        entity_id
        entity_type
        entity_name
        message
        from_id
        to_id
        changes {
          field
          changes_added
          changes_removed
        }
      }
    }
  }
`;

const AuditDrawerContent: FunctionComponent<{ logId: string }> = ({ logId }) => {
  const { t_i18n } = useFormatter();
  const { tz, locale, unitSystem } = useAuth();
  const variables = { id: logId, tz, locale, unit_system: unitSystem };
  const data = useLazyLoadQuery<AuditDrawerQuery>(auditDrawerQuery, variables);
  const log = data.audit;

  if (!log) return null;

  // We need to cast log to any or the expected type for useGenerateAuditMessage if strict
  // But generally it accepts an object with event_scope, etc.
  const message = useGenerateAuditMessage(log);

  const changes = log.context_data?.changes;
  const mappedChanges: Change[] = (changes ?? [])
    .filter((c): c is NonNullable<typeof c> => !!c)
    .map((c) => ({
      field: c.field,
      removed: c.changes_removed ?? [],
      added: c.changes_added ?? [],
    }));

  return (
    <Stack gap={2}>
      <Alert
        content={(
          <>
            <strong>{data?.audit?.user?.name}</strong> {message}
          </>
        )}
      />

      {log.context_uri && (
        <div>
          <Label>{t_i18n('Instance context')}</Label>
          <Link to={log.context_uri}>{t_i18n('View the element')}</Link>
        </div>
      )}

      {(log.context_data?.changes ?? []).length > 0 && (
        <ChangesTable
          changes={mappedChanges}
          variant="text"
        />
      )}

      {log.entity_type === 'Activity' && (
        <div>
          <Label>{t_i18n('Raw data')}</Label>
          <pre>{log.raw_data}</pre>
        </div>
      )}
    </Stack>
  );
};

const AuditDrawer: FunctionComponent<AuditDrawerProps> = ({ open, onClose, logId }) => {
  const { t_i18n } = useFormatter();

  return (
    <Drawer
      open={open}
      title={t_i18n('Activity raw detail')}
      onClose={onClose}
      size="medium"
    >
      <Suspense fallback={<Loader />}>
        <AuditDrawerContent logId={logId} />
      </Suspense>
    </Drawer>
  );
};

export default AuditDrawer;
