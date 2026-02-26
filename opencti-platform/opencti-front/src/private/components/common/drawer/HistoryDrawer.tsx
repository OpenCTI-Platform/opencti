import Drawer from '@components/common/drawer/Drawer';
import { Stack } from '@mui/material';
import { FunctionComponent, Suspense } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import Alert from '../../../../components/Alert';
import ChangesTable, { Change } from '../../../../components/common/table/ChangesTable';
import Loader from '../../../../components/Loader';
import useAuth from '../../../../utils/hooks/useAuth';
import { HistoryDrawerQuery } from './__generated__/HistoryDrawerQuery.graphql';
import MarkdownDisplay from '../../../../components/MarkdownDisplay';

interface HistoryDrawerProps {
  open: boolean;
  onClose: () => void;
  title: string;
  logId?: string;
}

const historyDrawerQuery = graphql`
  query HistoryDrawerQuery($id: ID!, $tz: String, $locale: String, $unit_system: String) {
    log(id: $id) {
      id
      user {
        name
      }
      context_data(tz: $tz, locale: $locale, unit_system: $unit_system) {
        entity_type
        message
        changes {
          field
          changes_added
          changes_removed
        }
      }
    }
  }
`;

interface HistoryDrawerContentProps {
  logId: string;
}

const HistoryDrawerContent: FunctionComponent<HistoryDrawerContentProps> = ({ logId }) => {
  const { locale, tz, unitSystem } = useAuth();
  const variables = { id: logId, tz, locale: locale, unit_system: unitSystem };
  const data = useLazyLoadQuery<HistoryDrawerQuery>(historyDrawerQuery, variables);

  const changes = data?.log?.context_data?.changes;
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
            <MarkdownDisplay
              content={data?.log?.context_data?.message ?? ''}
              remarkGfmPlugin={true}
              commonmark={true}
            />
          </>
        )}
      />

      <ChangesTable
        changes={mappedChanges}
        variant="text"
      />
    </Stack>
  );
};

const HistoryDrawer: FunctionComponent<HistoryDrawerProps> = ({ open, onClose, title, logId }) => {
  if (!logId) return null;

  return (
    <Drawer size="medium" open={open} onClose={onClose} title={title}>
      <Suspense fallback={<Loader />}>
        <HistoryDrawerContent logId={logId} />
      </Suspense>
    </Drawer>
  );
};

export default HistoryDrawer;
