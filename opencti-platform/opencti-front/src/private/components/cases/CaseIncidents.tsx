import React, { FunctionComponent, useState } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import {
  CaseIncidentsLinesCasesPaginationQuery,
  CaseIncidentsLinesCasesPaginationQuery$variables,
} from '@components/cases/__generated__/CaseIncidentsLinesCasesPaginationQuery.graphql';
import { CaseIncidentsLinesCases_data$data } from '@components/cases/__generated__/CaseIncidentsLinesCases_data.graphql';
import StixCoreObjectForms from '@components/common/stix_core_objects/StixCoreObjectForms';
import Box from '@mui/material/Box';
import Chip from '@mui/material/Chip';
import MuiTextField from '@mui/material/TextField';
import MenuItem from '@mui/material/MenuItem';
import Button from '@common/button/Button';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import useAuth from '../../../utils/hooks/useAuth';
import CaseIncidentCreation from './case_incidents/CaseIncidentCreation';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../utils/filters/filtersUtils';
import { useFormatter } from '../../../components/i18n';
import Breadcrumbs from '../../../components/Breadcrumbs';
import DataTable from '../../../components/dataGrid/DataTable';
import { DataTableProps } from '../../../components/dataGrid/dataTableTypes';
import { UsePreloadedPaginationFragment } from '../../../utils/hooks/usePreloadedPaginationFragment';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import { KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNASKIMPORT } from '../../../utils/hooks/useGranted';
import Security from '../../../utils/Security';
import { Filter } from '../../../utils/filters/filtersHelpers-types';

// --- Custom field definitions query ---
const customFieldDefinitionsForFilterQuery = graphql`
  query CaseIncidentsCustomFieldDefinitionsQuery($filters: FilterGroup) {
    customFieldDefinitions(filters: $filters) {
      edges {
        node {
          id
          name
          label
          field_type
          select_options
        }
      }
    }
  }
`;

interface CustomFieldDef {
  id: string;
  name: string;
  label: string;
  field_type: string;
  select_options?: ReadonlyArray<string> | null;
}

// --- Mini filter bar for custom fields ---
const CustomFieldFilterBar: FunctionComponent<{
  onAddFilter: (filter: Filter) => void;
}> = ({ onAddFilter }) => {
  const { t_i18n } = useFormatter();
  const [selectedDefId, setSelectedDefId] = useState('');
  const [inputValue, setInputValue] = useState('');

  const data = useLazyLoadQuery<any>(customFieldDefinitionsForFilterQuery, {
    filters: {
      mode: 'and',
      filters: [{ key: 'entity_types', values: ['Case-Incident'], operator: 'eq' }],
      filterGroups: [],
    },
  });
  const defs: CustomFieldDef[] = (data?.customFieldDefinitions?.edges ?? [])
    .map((e: any) => e?.node).filter(Boolean);

  // Always render the bar: show a hint when no definitions are associated
  const selectedDef = defs.find((d) => d.id === selectedDefId);

  const getValueSubFilterKey = (def: CustomFieldDef) => {
    if (def.field_type === 'integer') return 'int_value';
    if (def.field_type === 'select') return 'select_value';
    return 'string_value';
  };

  const handleApply = () => {
    if (!selectedDef || inputValue === '') return;
    const fieldName = `x_opencti_${selectedDef.name}`;
    const valueSubKey = getValueSubFilterKey(selectedDef);
    const filter: Filter = {
      key: 'customFieldValue',
      operator: 'eq',
      mode: 'and',
      values: [
        { key: 'field_name', values: [fieldName] },
        { key: valueSubKey, values: [inputValue] },
      ],
    };
    onAddFilter(filter);
    setInputValue('');
  };

  return (
    <Box
      sx={{
        display: 'flex',
        alignItems: 'flex-end',
        gap: 1.5,
        px: 1,
        py: 1,
        mb: 1,
        borderRadius: 1,
        border: '1px solid',
        borderColor: 'divider',
        backgroundColor: 'background.paper',
        flexWrap: 'wrap',
      }}
    >
      <Chip label={t_i18n('Custom field')} size="small" color="primary" variant="outlined" />
      {defs.length === 0 ? (
        <Box sx={{ fontSize: 12, color: 'text.secondary', alignSelf: 'center' }}>
          {t_i18n('No custom fields are associated to Incident Responses yet.')}
        </Box>
      ) : (
        <>
          {/* Field selector */}
          <MuiTextField
            select
            size="small"
            variant="standard"
            label={t_i18n('Field')}
            value={selectedDefId}
            onChange={(e) => { setSelectedDefId(e.target.value); setInputValue(''); }}
            sx={{ minWidth: 160 }}
          >
            <MenuItem value=""><em>—</em></MenuItem>
            {defs.map((d) => (
              <MenuItem key={d.id} value={d.id}>{d.label}</MenuItem>
            ))}
          </MuiTextField>
          {/* Value input — adapts to field type */}
          {selectedDef?.field_type === 'select' && selectedDef.select_options ? (
            <MuiTextField
              select
              size="small"
              variant="standard"
              label={t_i18n('Value')}
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              sx={{ minWidth: 140 }}
            >
              <MenuItem value=""><em>—</em></MenuItem>
              {selectedDef.select_options.map((opt) => (
                <MenuItem key={opt} value={opt}>{opt}</MenuItem>
              ))}
            </MuiTextField>
          ) : (
            <MuiTextField
              size="small"
              variant="standard"
              label={t_i18n('Value')}
              value={inputValue}
              type={selectedDef?.field_type === 'integer' ? 'number' : 'text'}
              onChange={(e) => setInputValue(e.target.value)}
              disabled={!selectedDef}
              sx={{ minWidth: 140 }}
              onKeyDown={(e) => { if (e.key === 'Enter') handleApply(); }}
            />
          )}
          <Button
            size="small"
            onClick={handleApply}
            disabled={!selectedDef || inputValue === ''}
          >
            {t_i18n('Filter')}
          </Button>
        </>
      )}
    </Box>
  );
};

interface CaseIncidentsProps {
  inputValue?: string;
}

const caseIncidentFragment = graphql`
  fragment CaseIncidentsLineCase_node on CaseIncident {
    id
    name
    description
    rating
    priority
    severity
    created
    entity_type
    response_types
    draftVersion {
      draft_id
      draft_operation
    }
    objectAssignee {
      entity_type
      id
      name
    }
    objectMarking {
      id
      definition_type
      definition
      x_opencti_order
      x_opencti_color
    }
    objectLabel {
      id
      value
      color
    }
    creators {
      id
      name
    }
    status {
      id
      order
      template {
        name
        color
      }
    }
    workflowEnabled
  }
`;

const caseIncidentsLinesQuery = graphql`
  query CaseIncidentsLinesCasesPaginationQuery(
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: CaseIncidentsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...CaseIncidentsLinesCases_data
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

const caseIncidentsLinesFragment = graphql`
  fragment CaseIncidentsLinesCases_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int" }
    cursor: { type: "ID" }
    orderBy: { type: "CaseIncidentsOrdering" }
    orderMode: { type: "OrderingMode", defaultValue: desc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "CaseIncidentsCasesLinesRefetchQuery") {
    caseIncidents(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_incidents_caseIncidents") {
      edges {
        node {
          id
          ...CaseIncidentsLineCase_node
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

export const LOCAL_STORAGE_KEY_CASE_INCIDENT = 'caseIncidents';

const CaseIncidents: FunctionComponent<CaseIncidentsProps> = () => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Incident Responses | Cases'));
  const { platformModuleHelpers: { isRuntimeFieldEnable } } = useAuth();

  const initialValues = {
    searchTerm: '',
    sortBy: 'created',
    orderAsc: false,
    openExports: false,
    filters: emptyFilterGroup,
  };
  const { viewStorage, helpers: storageHelpers, paginationOptions } = usePaginationLocalStorage<CaseIncidentsLinesCasesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY_CASE_INCIDENT,
    initialValues,
  );

  const {
    filters,
  } = viewStorage;

  const contextFilters = useBuildEntityTypeBasedFilterContext('Case-Incident', filters);
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as CaseIncidentsLinesCasesPaginationQuery$variables;
  const queryRef = useQueryLoading<CaseIncidentsLinesCasesPaginationQuery>(
    caseIncidentsLinesQuery,
    queryPaginationOptions,
  );

  const isRuntimeSort = isRuntimeFieldEnable() ?? false;
  const dataColumns: DataTableProps['dataColumns'] = {
    name: { percentWidth: 20 },
    priority: {},
    severity: {},
    objectAssignee: {
      label: 'Assignees',
      percentWidth: 14,
      isSortable: isRuntimeSort,
    },
    creator: {
      percentWidth: 10,
      isSortable: isRuntimeSort,
    },
    objectLabel: { percentWidth: 10 },
    created: { percentWidth: 10 },
    x_opencti_workflow_id: {},
    objectMarking: {
      isSortable: isRuntimeSort,
    },
  };

  const preloadedPaginationProps = {
    linesQuery: caseIncidentsLinesQuery,
    linesFragment: caseIncidentsLinesFragment,
    queryRef,
    nodePath: ['caseIncidents', 'pageInfo', 'globalCount'],
    setNumberOfElements: storageHelpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<CaseIncidentsLinesCasesPaginationQuery>;

  return (
    <div data-testid="incident-response-page">
      <Breadcrumbs elements={[{ label: t_i18n('Cases') }, { label: t_i18n('Incident responses'), current: true }]} />
      <CustomFieldFilterBar
        onAddFilter={(filter) => storageHelpers.handleAddFilterWithEmptyValue(filter)}
      />
      {queryRef && (
        <DataTable
          dataColumns={dataColumns}
          resolvePath={(data: CaseIncidentsLinesCases_data$data) => data.caseIncidents?.edges?.map((n) => n?.node)}
          storageKey={LOCAL_STORAGE_KEY_CASE_INCIDENT}
          initialValues={initialValues}
          contextFilters={contextFilters}
          preloadedPaginationProps={preloadedPaginationProps}
          lineFragment={caseIncidentFragment}
          exportContext={{ entity_type: 'Case-Incident' }}
          additionalHeaderButtons={[
            <Security key="form-intake" needs={[KNOWLEDGE_KNUPDATE]} capabilitiesInDraft={[KNOWLEDGE_KNASKIMPORT]}>
              <StixCoreObjectForms entityType="Case-Incident" />
            </Security>,
          ]}
          createButton={(
            <Security needs={[KNOWLEDGE_KNUPDATE]}>
              <CaseIncidentCreation paginationOptions={queryPaginationOptions} />
            </Security>
          )}
        />
      )}
    </div>
  );
};

export default CaseIncidents;
