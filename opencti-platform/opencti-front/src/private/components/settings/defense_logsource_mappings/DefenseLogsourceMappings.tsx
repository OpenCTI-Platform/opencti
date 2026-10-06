import React, { Suspense, useState } from 'react';
import { graphql, PreloadedQuery, usePaginationFragment, usePreloadedQuery } from 'react-relay';
import { Box, DialogActions, Stack, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Typography } from '@mui/material';
import { DeleteOutlined, DeviceHubOutlined, EditOutlined } from '@mui/icons-material';
import { Button as DsButton, Chip, Hero, HeroBody, HeroHeader, IconButton, Switch, Text, Thumbnail, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import PageContainer from '../../../../components/PageContainer';
import Card from '../../../../components/common/card/Card';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import SearchInput from '../../../../components/SearchInput';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { MESSAGING$ } from '../../../../relay/environment';
import { notifyPayloadErrors } from '../../defense/matrix/defenseMutation-utils';
import {
  DefenseLogsourceMappingsLinesPaginationQuery,
  DefenseLogsourceMappingsLinesPaginationQuery$variables,
} from './__generated__/DefenseLogsourceMappingsLinesPaginationQuery.graphql';
import { DefenseLogsourceMappingsLines_data$key } from './__generated__/DefenseLogsourceMappingsLines_data.graphql';
import { DefenseLogsourceMappingsLinesRefetchQuery } from './__generated__/DefenseLogsourceMappingsLinesRefetchQuery.graphql';
import { DefenseLogsourceMappingsDeleteMutation } from './__generated__/DefenseLogsourceMappingsDeleteMutation.graphql';
import { DefenseLogsourceMappingsResetMutation } from './__generated__/DefenseLogsourceMappingsResetMutation.graphql';
import { DefenseLogsourceMappingsActiveMutation } from './__generated__/DefenseLogsourceMappingsActiveMutation.graphql';
import DefenseLogsourceMappingForm, { type DefenseLogsourceMappingFormData } from './DefenseLogsourceMappingForm';

const PAGE_SIZE = 100;

// The custom mappings, counted apart from the paginated list: one may sort after the first page
const CUSTOM_MAPPINGS_FILTERS: DefenseLogsourceMappingsLinesPaginationQuery$variables['customFilters'] = {
  mode: 'and',
  filters: [{ key: ['built_in'], values: ['false'], operator: 'eq', mode: 'or' }],
  filterGroups: [],
};

const defenseLogsourceMappingsLinesQuery = graphql`
  query DefenseLogsourceMappingsLinesPaginationQuery($search: String, $count: Int!, $cursor: ID, $customFilters: FilterGroup) {
    ...DefenseLogsourceMappingsLines_data @arguments(search: $search, count: $count, cursor: $cursor, customFilters: $customFilters)
  }
`;

const defenseLogsourceMappingsLinesFragment = graphql`
  fragment DefenseLogsourceMappingsLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 100 }
    cursor: { type: "ID" }
    customFilters: { type: "FilterGroup" }
  ) @refetchable(queryName: "DefenseLogsourceMappingsLinesRefetchQuery") {
    customMappings: defenseLogsourceMappings(first: 1, filters: $customFilters) {
      pageInfo {
        globalCount
      }
    }
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

const DOCUMENTATION_URL = 'https://docs.opencti.io/latest/usage/defense-matrix/';

/**
 * First-use state of the page, until a mapping of the organization is added: what a mapping does, with
 * the action that adds one.
 */
const MappingsFirstUse = ({ onCreate }: { onCreate: () => void }) => {
  const { t_i18n } = useFormatter();
  return (
    <Hero data-testid="defense-logsource-mappings-first-use">
      <HeroHeader
        icon={<Thumbnail><DeviceHubOutlined /></Thumbnail>}
        action={<Button onClick={onCreate} data-testid="defense-logsource-mappings-first-use-create">{t_i18n('Add a mapping')}</Button>}
      >
        <Text variant="title-md">{t_i18n('Tell the defense matrix what your telemetry covers')}</Text>
      </HeroHeader>
      <HeroBody>
        <Text variant="content-base">
          {t_i18n('A mapping links a log source (for example Windows process creation events collected by Sysmon) to the MITRE data sources it feeds.')}
        </Text>
        <DsButton priority="tertiary" size="sm" asChild>
          <a href={DOCUMENTATION_URL} target="_blank" rel="noreferrer">{t_i18n('Read the documentation')}</a>
        </DsButton>
      </HeroBody>
    </Hero>
  );
};

const MappingsTable = ({ queryRef, onEdit, onCreate, onFirstUseChange, searching, refreshKey }: {
  queryRef: PreloadedQuery<DefenseLogsourceMappingsLinesPaginationQuery>;
  onEdit: (mapping: DefenseLogsourceMappingFormData) => void;
  onCreate: () => void;
  onFirstUseChange: (firstUse: boolean) => void;
  searching: boolean;
  refreshKey: number;
}) => {
  const { t_i18n, fldt, rd } = useFormatter();
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
  const firstUse = !searching && (data.customMappings?.pageInfo.globalCount ?? 0) === 0;
  // The first-use card carries the creation action: the page header does not repeat it
  React.useEffect(() => onFirstUseChange(firstUse), [firstUse]);

  return (
    <>
      {firstUse && <MappingsFirstUse onCreate={onCreate} />}
      <Card>
        {/* The count stays out of the card title, which capitalizes every word */}
        <Typography variant="body2" color="text.secondary" sx={{ marginBottom: 1 }} data-testid="defense-logsource-mappings-count">
          {t_i18n('{count, plural, one {# telemetry mapping} other {# telemetry mappings}}', { values: { count: data.defenseLogsourceMappings?.pageInfo.globalCount ?? 0 } })}
        </Typography>
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
                      <TableCell sx={{ whiteSpace: 'nowrap' }}>{mapping.built_in ? t_i18n('Built-in') : t_i18n('Custom')}</TableCell>
                      <TableCell sx={{ whiteSpace: 'nowrap' }}>
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <span tabIndex={0} style={{ cursor: 'help' }}>{rd(mapping.updated_at)}</span>
                          </TooltipTrigger>
                          <TooltipContent>{fldt(mapping.updated_at)}</TooltipContent>
                        </Tooltip>
                      </TableCell>
                      <TableCell>
                        <Switch
                          aria-label={t_i18n('Active')}
                          checked={mapping.active}
                          onCheckedChange={(checked) => commitActive({
                            variables: { id: mapping.id, input: [{ key: 'active', value: [checked] }] },
                            onCompleted: (_, errors) => {
                              notifyPayloadErrors(errors);
                            },
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
    </>
  );
};

const DefenseLogsourceMappings = () => {
  const { t_i18n } = useFormatter();
  const [search, setSearch] = useState('');
  const [formOpen, setFormOpen] = useState(false);
  const [edited, setEdited] = useState<DefenseLogsourceMappingFormData | null>(null);
  const [resetOpen, setResetOpen] = useState(false);
  const [refreshKey, setRefreshKey] = useState(0);
  const [firstUse, setFirstUse] = useState(false);
  const queryRef = useQueryLoading<DefenseLogsourceMappingsLinesPaginationQuery>(defenseLogsourceMappingsLinesQuery, {
    search: search.length > 0 ? search : null,
    count: PAGE_SIZE,
    customFilters: CUSTOM_MAPPINGS_FILTERS,
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
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
          <SearchInput variant="thin" onSubmit={setSearch} />
          <Stack direction="row" spacing={1} sx={{ marginLeft: 'auto' }}>
            <Button variant="secondary" onClick={() => setResetOpen(true)} data-testid="defense-logsource-mappings-reset">
              {t_i18n('Restore built-in mappings')}
            </Button>
            {!firstUse && (
              <Button
                onClick={() => {
                  setEdited(null);
                  setFormOpen(true);
                }}
                data-testid="defense-logsource-mappings-create"
              >
                {t_i18n('Add a mapping')}
              </Button>
            )}
          </Stack>
        </Box>
        {queryRef && (
          <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
            <MappingsTable
              queryRef={queryRef}
              refreshKey={refreshKey}
              searching={search.length > 0}
              onFirstUseChange={setFirstUse}
              onCreate={() => {
                setEdited(null);
                setFormOpen(true);
              }}
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
