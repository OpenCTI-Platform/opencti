import React, { Suspense, useState } from 'react';
import { graphql, PreloadedQuery, usePaginationFragment, usePreloadedQuery } from 'react-relay';
import { Box, DialogActions, Stack, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Typography } from '@mui/material';
import { DeleteOutlined, EditOutlined } from '@mui/icons-material';
import { Chip, IconButton, Switch } from '@filigran/design-system';
import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import PageContainer from '../../../../components/PageContainer';
import Alert from '../../../../components/Alert';
import Card from '../../../../components/common/card/Card';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import SearchInput from '../../../../components/SearchInput';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { MESSAGING$ } from '../../../../relay/environment';
import { notifyPayloadErrors } from '../../defense/matrix/defenseMutation-utils';
import { DefenseLogsourceMappingsLinesPaginationQuery } from './__generated__/DefenseLogsourceMappingsLinesPaginationQuery.graphql';
import { DefenseLogsourceMappingsLines_data$key } from './__generated__/DefenseLogsourceMappingsLines_data.graphql';
import { DefenseLogsourceMappingsLinesRefetchQuery } from './__generated__/DefenseLogsourceMappingsLinesRefetchQuery.graphql';
import { DefenseLogsourceMappingsDeleteMutation } from './__generated__/DefenseLogsourceMappingsDeleteMutation.graphql';
import { DefenseLogsourceMappingsResetMutation } from './__generated__/DefenseLogsourceMappingsResetMutation.graphql';
import { DefenseLogsourceMappingsActiveMutation } from './__generated__/DefenseLogsourceMappingsActiveMutation.graphql';
import DefenseLogsourceMappingForm, { type DefenseLogsourceMappingFormData } from './DefenseLogsourceMappingForm';

const PAGE_SIZE = 100;

const defenseLogsourceMappingsLinesQuery = graphql`
  query DefenseLogsourceMappingsLinesPaginationQuery($search: String, $count: Int!, $cursor: ID) {
    ...DefenseLogsourceMappingsLines_data @arguments(search: $search, count: $count, cursor: $cursor)
  }
`;

const defenseLogsourceMappingsLinesFragment = graphql`
  fragment DefenseLogsourceMappingsLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 100 }
    cursor: { type: "ID" }
  ) @refetchable(queryName: "DefenseLogsourceMappingsLinesRefetchQuery") {
    defenseLogsourceMappings(search: $search, first: $count, after: $cursor, orderBy: name, orderMode: asc)
    @connection(key: "Pagination_defenseLogsourceMappings") {
      edges {
        node {
          id
          name
          description
          logsource_category
          logsource_product
          logsource_service
          data_components
          resolvedDataComponents {
            id
            name
          }
          active
          built_in
          updated_at
        }
      }
      pageInfo {
        endCursor
        hasNextPage
        globalCount
      }
    }
  }
`;

const defenseLogsourceMappingsDeleteMutation = graphql`
  mutation DefenseLogsourceMappingsDeleteMutation($id: ID!) {
    defenseLogsourceMappingDelete(id: $id)
  }
`;

const defenseLogsourceMappingsResetMutation = graphql`
  mutation DefenseLogsourceMappingsResetMutation {
    defenseLogsourceMappingsReset
  }
`;

const defenseLogsourceMappingsActiveMutation = graphql`
  mutation DefenseLogsourceMappingsActiveMutation($id: ID!, $input: [EditInput!]!) {
    defenseLogsourceMappingFieldPatch(id: $id, input: $input) {
      id
      active
    }
  }
`;

const MappingsTable = ({ queryRef, onEdit, refreshKey }: {
  queryRef: PreloadedQuery<DefenseLogsourceMappingsLinesPaginationQuery>;
  onEdit: (mapping: DefenseLogsourceMappingFormData) => void;
  refreshKey: number;
}) => {
  const { t_i18n, fldt } = useFormatter();
  const queryData = usePreloadedQuery(defenseLogsourceMappingsLinesQuery, queryRef);
  const { data, hasNext, loadNext, isLoadingNext, refetch } = usePaginationFragment<DefenseLogsourceMappingsLinesRefetchQuery, DefenseLogsourceMappingsLines_data$key>(
    defenseLogsourceMappingsLinesFragment,
    queryData,
  );
  const [toDelete, setToDelete] = useState<{ id: string; name: string } | null>(null);
  const [commitDelete, deleting] = useApiMutation<DefenseLogsourceMappingsDeleteMutation>(defenseLogsourceMappingsDeleteMutation);
  const [commitActive] = useApiMutation<DefenseLogsourceMappingsActiveMutation>(defenseLogsourceMappingsActiveMutation);
  React.useEffect(() => {
    if (refreshKey > 0) refetch({}, { fetchPolicy: 'network-only' });
  }, [refreshKey]);
  const mappings = (data.defenseLogsourceMappings?.edges ?? []).map(({ node }) => node);

  return (
    <Card title={t_i18n('{count} telemetry mappings', { values: { count: data.defenseLogsourceMappings?.pageInfo.globalCount ?? 0 } })}>
      {mappings.length === 0 ? (
        <Typography variant="body2" color="text.secondary">{t_i18n('No telemetry mapping matches the search.')}</Typography>
      ) : (
        <TableContainer>
          <Table size="small" aria-label={t_i18n('Telemetry mappings')} data-testid="defense-logsource-mappings-table">
            <TableHead>
              <TableRow>
                <TableCell>{t_i18n('Log source')}</TableCell>
                <TableCell>{t_i18n('Data components')}</TableCell>
                <TableCell>{t_i18n('Description')}</TableCell>
                <TableCell>{t_i18n('Origin')}</TableCell>
                <TableCell>{t_i18n('Modification date')}</TableCell>
                <TableCell>{t_i18n('Active')}</TableCell>
                <TableCell align="right">{t_i18n('Actions')}</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {mappings.map((mapping) => {
                const resolved = new Set(mapping.resolvedDataComponents.map((dc) => dc.name.toLowerCase()));
                return (
                  <TableRow key={mapping.id} hover data-testid={`defense-logsource-mapping-${mapping.name}`}>
                    <TableCell sx={{ fontFamily: 'monospace' }}>{mapping.name}</TableCell>
                    <TableCell>
                      <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap>
                        {mapping.data_components.map((name) => (
                          <Chip
                            key={name}
                            label={name}
                            severity={resolved.has(name.toLowerCase()) ? 'neutral' : 'medium'}
                            title={resolved.has(name.toLowerCase()) ? undefined : t_i18n('This data component is not present in the platform')}
                          />
                        ))}
                      </Stack>
                    </TableCell>
                    <TableCell>{mapping.description ?? '-'}</TableCell>
                    <TableCell>{mapping.built_in ? t_i18n('Built-in') : t_i18n('Custom')}</TableCell>
                    <TableCell>{fldt(mapping.updated_at)}</TableCell>
                    <TableCell>
                      <Switch
                        aria-label={t_i18n('Active')}
                        checked={mapping.active}
                        onCheckedChange={(checked) => commitActive({
                          variables: { id: mapping.id, input: [{ key: 'active', value: [checked] }] },
                          onCompleted: (_, errors) => notifyPayloadErrors(errors),
                        })}
                      />
                    </TableCell>
                    <TableCell align="right">
                      <Stack direction="row" spacing={0.5} justifyContent="flex-end">
                        <IconButton
                          size="sm"
                          priority="tertiary"
                          aria-label={t_i18n('Update')}
                          icon={<EditOutlined fontSize="small" />}
                          onClick={() => onEdit(mapping)}
                        />
                        {!mapping.built_in && (
                          <IconButton
                            size="sm"
                            priority="tertiary"
                            aria-label={t_i18n('Delete')}
                            icon={<DeleteOutlined fontSize="small" />}
                            onClick={() => setToDelete({ id: mapping.id, name: mapping.name })}
                          />
                        )}
                      </Stack>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </TableContainer>
      )}
      {hasNext && (
        <Box sx={{ display: 'flex', justifyContent: 'center', marginTop: 2 }}>
          <Button variant="secondary" disabled={isLoadingNext} onClick={() => loadNext(PAGE_SIZE)}>{t_i18n('Load more')}</Button>
        </Box>
      )}
      <Dialog open={!!toDelete} onClose={() => setToDelete(null)} title={t_i18n('Are you sure?')} size="small">
        <Typography>{t_i18n('Do you want to delete the telemetry mapping {name}?', { values: { name: toDelete?.name ?? '' } })}</Typography>
        <DialogActions>
          <Button variant="secondary" onClick={() => setToDelete(null)} disabled={deleting}>{t_i18n('Cancel')}</Button>
          <Button
            intent="destructive"
            disabled={deleting}
            onClick={() => toDelete && commitDelete({
              variables: { id: toDelete.id },
              onCompleted: (_, errors) => {
                if (notifyPayloadErrors(errors)) return;
                MESSAGING$.notifySuccess(t_i18n('Telemetry mapping deleted'));
                setToDelete(null);
                refetch({}, { fetchPolicy: 'network-only' });
              },
            })}
          >
            {t_i18n('Delete')}
          </Button>
        </DialogActions>
      </Dialog>
    </Card>
  );
};

const DefenseLogsourceMappings = () => {
  const { t_i18n } = useFormatter();
  const [search, setSearch] = useState('');
  const [formOpen, setFormOpen] = useState(false);
  const [edited, setEdited] = useState<DefenseLogsourceMappingFormData | null>(null);
  const [resetOpen, setResetOpen] = useState(false);
  const [refreshKey, setRefreshKey] = useState(0);
  const queryRef = useQueryLoading<DefenseLogsourceMappingsLinesPaginationQuery>(defenseLogsourceMappingsLinesQuery, {
    search: search.length > 0 ? search : null,
    count: PAGE_SIZE,
  });
  const [commitReset, resetting] = useApiMutation<DefenseLogsourceMappingsResetMutation>(defenseLogsourceMappingsResetMutation);
  const refresh = () => setRefreshKey((key) => key + 1);

  return (
    <div data-testid="defense-logsource-mappings-page">
      <PageContainer withGap withRightMenu>
        <Breadcrumbs
          noMargin
          elements={[{ label: t_i18n('Settings') }, { label: t_i18n('Customization') }, { label: t_i18n('Telemetry mappings'), current: true }]}
        />
        <Alert
          content={t_i18n('Telemetry mappings turn the log sources of detection rules and security platforms (Sigma taxonomy) into MITRE data components. The defense matrix uses them to infer the telemetry of a platform from its deployed rules and to declare telemetry from log sources.')}
        />
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
          <SearchInput variant="thin" onSubmit={setSearch} />
          <Stack direction="row" spacing={1} sx={{ marginLeft: 'auto' }}>
            <Button variant="secondary" onClick={() => setResetOpen(true)} data-testid="defense-logsource-mappings-reset">
              {t_i18n('Restore built-in mappings')}
            </Button>
            <Button
              onClick={() => {
                setEdited(null);
                setFormOpen(true);
              }}
              data-testid="defense-logsource-mappings-create"
            >
              {t_i18n('Create a telemetry mapping')}
            </Button>
          </Stack>
        </Box>
        {queryRef && (
          <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
            <MappingsTable
              queryRef={queryRef}
              refreshKey={refreshKey}
              onEdit={(mapping) => {
                setEdited(mapping);
                setFormOpen(true);
              }}
            />
          </Suspense>
        )}
      </PageContainer>
      <DefenseLogsourceMappingForm open={formOpen} mapping={edited} onClose={() => setFormOpen(false)} onSaved={refresh} />
      <Dialog open={resetOpen} onClose={() => setResetOpen(false)} title={t_i18n('Restore built-in mappings')} size="small">
        <Typography>
          {t_i18n('Every built-in mapping gets back its shipped data components and is reactivated. Custom mappings are kept.')}
        </Typography>
        <DialogActions>
          <Button variant="secondary" onClick={() => setResetOpen(false)} disabled={resetting}>{t_i18n('Cancel')}</Button>
          <Button
            disabled={resetting}
            data-testid="defense-logsource-mappings-reset-confirm"
            onClick={() => commitReset({
              variables: {},
              onCompleted: (response, errors) => {
                if (notifyPayloadErrors(errors) || response.defenseLogsourceMappingsReset == null) return;
                setResetOpen(false);
                refresh();
                MESSAGING$.notifySuccess(t_i18n('{count} built-in mappings restored', { values: { count: response.defenseLogsourceMappingsReset ?? 0 } }));
              },
            })}
          >
            {t_i18n('Restore')}
          </Button>
        </DialogActions>
      </Dialog>
    </div>
  );
};

export default DefenseLogsourceMappings;
