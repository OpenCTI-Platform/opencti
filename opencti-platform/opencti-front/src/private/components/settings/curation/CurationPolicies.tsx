import { useState } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import Box from '@mui/material/Box';
import DialogActions from '@mui/material/DialogActions';
import Typography from '@mui/material/Typography';
import { DeleteOutlined, EditOutlined, PlayArrowOutlined, ScienceOutlined } from '@mui/icons-material';
import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import Dialog from '@common/dialog/Dialog';
import Tag from '@common/tag/Tag';
import EnterpriseEdition from '@components/common/entreprise_edition/EnterpriseEdition';
import DataTable from '../../../../components/dataGrid/DataTable';
import { DataTableProps } from '../../../../components/dataGrid/dataTableTypes';
import { useFormatter } from '../../../../components/i18n';
import ItemBoolean from '../../../../components/ItemBoolean';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import useGranted, { KNOWLEDGE_KNUPDATE, SETTINGS_SETCUSTOMIZATION } from '../../../../utils/hooks/useGranted';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { emptyFilterGroup, isFilterGroupNotEmpty, useBuildEntityTypeBasedFilterContext } from '../../../../utils/filters/filtersUtils';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import { useQueryLoadingWithLoadQuery } from '../../../../utils/hooks/useQueryLoading';
import { MESSAGING$ } from '../../../../relay/environment';
import CurationPolicyDryRun from './CurationPolicyDryRun';
import CurationPolicyForm, { CurationPolicyFormData } from './CurationPolicyForm';
import useCurationLabels, { formatPercent, notifyPayloadErrors } from '../../data/curation/curationUtils';
import { CurationPoliciesListQuery, CurationPoliciesListQuery$variables } from './__generated__/CurationPoliciesListQuery.graphql';
import { CurationPolicies_policies$data } from './__generated__/CurationPolicies_policies.graphql';
import { CurationPolicies_policy$data } from './__generated__/CurationPolicies_policy.graphql';
import { CurationPoliciesSettingsQuery } from './__generated__/CurationPoliciesSettingsQuery.graphql';
import { CurationPoliciesApplyMutation } from './__generated__/CurationPoliciesApplyMutation.graphql';
import { CurationPoliciesDeleteMutation } from './__generated__/CurationPoliciesDeleteMutation.graphql';

const policyFragment = graphql`
  fragment CurationPolicies_policy on CurationPolicy {
    id
    entity_type
    name
    description
    policy_enabled
    policy_entity_types
    policy_kinds
    policy_source_class
    auto_apply_threshold
    forbid_open_contradiction
    require_adjudication
    max_applies_per_run
    last_applied_at
    applied_count
    updated_at
  }
`;

const policiesFragment = graphql`
  fragment CurationPolicies_policies on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "CurationPolicyOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "CurationPoliciesRefetchQuery") {
    curationPolicies(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_curationPolicies") {
      edges {
        node {
          id
          ...CurationPolicies_policy
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

const policiesListQuery = graphql`
  query CurationPoliciesListQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: CurationPolicyOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...CurationPolicies_policies
    @arguments(
      search: $search
      count: $count
      cursor: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    )
  }
`;

const policiesSettingsQuery = graphql`
  query CurationPoliciesSettingsQuery {
    curationSettings {
      curated_entity_types
    }
  }
`;

const policyApplyMutation = graphql`
  mutation CurationPoliciesApplyMutation($id: ID!) {
    curationPolicyApply(id: $id)
  }
`;

const policyDeleteMutation = graphql`
  mutation CurationPoliciesDeleteMutation($id: ID!) {
    curationPolicyDelete(id: $id)
  }
`;

const LOCAL_STORAGE_KEY = 'curation_policies';

const CurationPoliciesComponent = () => {
  const { t_i18n, fldt, n } = useFormatter();
  const labels = useCurationLabels();
  const isGrantedToSettings = useGranted([SETTINGS_SETCUSTOMIZATION]);
  const canApplyProposals = useGranted([KNOWLEDGE_KNUPDATE]);
  const { curationSettings } = useLazyLoadQuery<CurationPoliciesSettingsQuery>(policiesSettingsQuery, {});
  const [formOpen, setFormOpen] = useState(false);
  const [editing, setEditing] = useState<CurationPolicyFormData | null>(null);
  const [dryRun, setDryRun] = useState<{ id: string; name: string } | null>(null);
  const [deleting, setDeleting] = useState<{ id: string; name: string } | null>(null);
  const [commitApply, applying] = useApiMutation<CurationPoliciesApplyMutation>(policyApplyMutation);
  const [commitDelete, deletingInFlight] = useApiMutation<CurationPoliciesDeleteMutation>(policyDeleteMutation);

  const initialValues = {
    searchTerm: '',
    sortBy: 'name',
    orderAsc: true,
    openExports: false,
    filters: emptyFilterGroup,
  };
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<CurationPoliciesListQuery$variables>(LOCAL_STORAGE_KEY, initialValues);
  const contextFilters = useBuildEntityTypeBasedFilterContext('CurationPolicy', viewStorage.filters);
  const queryPaginationOptions = { ...paginationOptions, filters: contextFilters } as unknown as CurationPoliciesListQuery$variables;
  const [queryRef, loadQuery] = useQueryLoadingWithLoadQuery<CurationPoliciesListQuery>(policiesListQuery, queryPaginationOptions);
  const refresh = () => loadQuery(queryPaginationOptions, { fetchPolicy: 'network-only' });

  const apply = (policy: CurationPolicies_policy$data) => {
    commitApply({
      variables: { id: policy.id },
      onCompleted: (response, errors) => {
        if (notifyPayloadErrors(errors)) return;
        MESSAGING$.notifySuccess(response.curationPolicyApply
          ? t_i18n('The eligible proposals are being applied by a background task')
          : t_i18n('No proposal you can accept is eligible for this policy'));
      },
    });
  };

  const confirmDelete = () => {
    if (!deleting) return;
    commitDelete({
      variables: { id: deleting.id },
      onCompleted: (_, errors) => {
        if (notifyPayloadErrors(errors)) return;
        MESSAGING$.notifySuccess(t_i18n('The curation policy has been deleted'));
        setDeleting(null);
        refresh();
      },
    });
  };

  const dataColumns: DataTableProps['dataColumns'] = {
    name: { id: 'name', label: 'Name', percentWidth: 16, isSortable: true },
    policy_kinds: {
      id: 'policy_kinds',
      label: 'Proposal kinds',
      percentWidth: 16,
      isSortable: false,
      render: ({ policy_kinds }: CurationPolicies_policy$data) => (
        <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
          {policy_kinds.map((kind) => <Tag key={kind} label={labels.kind(kind)} />)}
        </Box>
      ),
    },
    policy_entity_types: {
      id: 'policy_entity_types',
      label: 'Entity types',
      percentWidth: 12,
      isSortable: false,
      render: ({ policy_entity_types }: CurationPolicies_policy$data) => (policy_entity_types.length === 0
        ? t_i18n('All curated types')
        : policy_entity_types.map((type) => t_i18n(`entity_${type}`)).join(', ')),
    },
    auto_apply_threshold: {
      id: 'auto_apply_threshold',
      label: 'Auto-apply threshold',
      percentWidth: 18,
      isSortable: true,
      render: ({ auto_apply_threshold }: CurationPolicies_policy$data) => formatPercent(auto_apply_threshold),
    },
    applied_count: {
      id: 'applied_count',
      label: 'Applied proposals',
      percentWidth: 14,
      isSortable: false,
      render: ({ applied_count }: CurationPolicies_policy$data) => n(applied_count),
    },
    last_applied_at: {
      id: 'last_applied_at',
      label: 'Last applied',
      percentWidth: 12,
      isSortable: false,
      render: ({ last_applied_at }: CurationPolicies_policy$data) => (last_applied_at ? fldt(last_applied_at) : '-'),
    },
    policy_enabled: {
      id: 'policy_enabled',
      label: 'Status',
      percentWidth: 8,
      isSortable: false,
      render: ({ policy_enabled }: CurationPolicies_policy$data) => (
        <ItemBoolean label={policy_enabled ? t_i18n('Enabled') : t_i18n('Disabled')} status={policy_enabled} />
      ),
    },
  };

  return (
    <>
      <Box sx={{ display: 'flex', alignItems: 'center', marginBottom: 2 }}>
        <Typography variant="body2" sx={{ flex: 1 }}>
          {t_i18n('Curation policies apply eligible proposals automatically through background tasks, never across markings or organizations. Most applied proposals can be reverted: a merge until its merge record expires; a date fix cannot be reverted.')}
        </Typography>
        {isGrantedToSettings && (
          <Button
            onClick={() => {
              setEditing(null);
              setFormOpen(true);
            }}
            data-testid="curation-policy-create"
          >
            {t_i18n('Create a curation policy')}
          </Button>
        )}
      </Box>
      {queryRef && (
        <DataTable
          removeSelectAll
          disableLineSelection
          disableNavigation
          dataColumns={dataColumns}
          resolvePath={(data: CurationPolicies_policies$data) => data.curationPolicies?.edges?.map((edge) => edge?.node)}
          storageKey={LOCAL_STORAGE_KEY}
          initialValues={initialValues}
          contextFilters={contextFilters}
          emptyStateMessage={viewStorage.searchTerm || isFilterGroupNotEmpty(viewStorage.filters) ? undefined : (
            <span data-testid="curation-policies-empty">
              {t_i18n('No curation policy yet. Create one to apply the eligible proposals automatically; until then, every proposal waits for an analyst.')}
            </span>
          )}
          preloadedPaginationProps={{
            linesQuery: policiesListQuery,
            linesFragment: policiesFragment,
            queryRef,
            nodePath: ['curationPolicies', 'pageInfo', 'globalCount'],
            setNumberOfElements: helpers.handleSetNumberOfElements,
          }}
          lineFragment={policyFragment}
          entityTypes={['CurationPolicy']}
          searchContextFinal={{ entityTypes: ['CurationPolicy'] }}
          actionsColumnWidth={isGrantedToSettings ? 168 : undefined}
          actions={isGrantedToSettings ? (policy: CurationPolicies_policy$data) => (
            <Box sx={{ display: 'flex' }}>
              <IconButton size="small" aria-label={t_i18n('Dry run')} title={t_i18n('Dry run')} onClick={() => setDryRun({ id: policy.id, name: policy.name })}>
                <ScienceOutlined fontSize="small" />
              </IconButton>
              <span title={canApplyProposals ? t_i18n('Apply now') : t_i18n('Applying proposals also requires the Update knowledge capability')}>
                <IconButton size="small" aria-label={t_i18n('Apply now')} disabled={applying || !canApplyProposals} onClick={() => apply(policy)}>
                  <PlayArrowOutlined fontSize="small" />
                </IconButton>
              </span>
              <IconButton
                size="small"
                aria-label={t_i18n('Update')}
                title={t_i18n('Update')}
                onClick={() => {
                  setEditing(policy);
                  setFormOpen(true);
                }}
              >
                <EditOutlined fontSize="small" />
              </IconButton>
              <IconButton size="small" aria-label={t_i18n('Delete')} title={t_i18n('Delete')} onClick={() => setDeleting({ id: policy.id, name: policy.name })}>
                <DeleteOutlined fontSize="small" />
              </IconButton>
            </Box>
          ) : undefined}
        />
      )}
      <CurationPolicyForm
        open={formOpen}
        onClose={() => setFormOpen(false)}
        onSaved={refresh}
        policy={editing}
        curatedEntityTypes={curationSettings.curated_entity_types}
      />
      <CurationPolicyDryRun policyId={dryRun?.id ?? null} policyName={dryRun?.name} onClose={() => setDryRun(null)} />
      <Dialog open={!!deleting} onClose={() => setDeleting(null)} title={t_i18n('Delete the curation policy')}>
        <Typography variant="body2">
          {t_i18n('Do you want to delete this curation policy?')} {deleting?.name}
        </Typography>
        <DialogActions>
          <Button variant="secondary" onClick={() => setDeleting(null)} disabled={deletingInFlight}>
            {t_i18n('Cancel')}
          </Button>
          <Button intent="destructive" onClick={confirmDelete} disabled={deletingInFlight}>
            {t_i18n('Delete')}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
};

const CurationPolicies = () => {
  const { t_i18n } = useFormatter();
  const isEnterpriseEdition = useEnterpriseEdition();
  return (
    <div data-testid="curation-policies-page">
      {isEnterpriseEdition ? <CurationPoliciesComponent /> : <EnterpriseEdition feature={t_i18n('Curation policies')} />}
    </div>
  );
};

export default CurationPolicies;
