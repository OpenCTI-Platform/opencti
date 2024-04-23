import React, { FunctionComponent } from 'react';
import {
  EntityStixSightingRelationshipsLinesPaginationQuery,
  EntityStixSightingRelationshipsLinesPaginationQuery$variables,
} from '@components/events/stix_sighting_relationships/__generated__/EntityStixSightingRelationshipsLinesPaginationQuery.graphql';
import makeStyles from '@mui/styles/makeStyles';
import { EntityStixSightingRelationshipLineDummy } from '@components/events/stix_sighting_relationships/EntityStixSightingRelationshipLine';
import useHelper from 'src/utils/hooks/useHelper';
import ListLines from '../../../../components/list_lines/ListLines';
import EntityStixSightingRelationshipsLines, { entityStixSightingRelationshipsLinesQuery } from './EntityStixSightingRelationshipsLines';
import StixSightingRelationshipCreationFromEntity from './StixSightingRelationshipCreationFromEntity';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { emptyFilterGroup, useRemoveIdAndIncorrectKeysFromFilterGroupObject, isFilterGroupNotEmpty } from '../../../../utils/filters/filtersUtils';
import { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';

export const LOCAL_STORAGE_KEY = 'sightings';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  container: {
    marginTop: 15,
    paddingBottom: 70,
  },
}));

interface SightingCreationComponentProps {
  isTo: boolean,
  entityId: string,
  noPadding?: boolean,
  paginationOptions: EntityStixSightingRelationshipsLinesPaginationQuery$variables
  stixCoreObjectTypes: string[],
  variant?: string,
}

const SightingCreationComponent: FunctionComponent<SightingCreationComponentProps> = ({
  isTo,
  entityId,
  noPadding,
  paginationOptions,
  stixCoreObjectTypes,
  variant,
}) => (
  <Security needs={[KNOWLEDGE_KNUPDATE]}>
    {isTo ? (
      <StixSightingRelationshipCreationFromEntity
        entityId={entityId}
        isTo={true}
        stixCoreObjectTypes={[
          'Threat-Actor',
          'Intrusion-Set',
          'Campaign',
          'Malware',
          'Tool',
          'Vulnerability',
          'Indicator',
        ]}
        targetStixCyberObservableTypes={['Stix-Cyber-Observable']}
        paddingRight={noPadding ? null : 220}
        paginationOptions={paginationOptions}
        variant={variant}
        onCreate={undefined}
      />
    ) : (
      <StixSightingRelationshipCreationFromEntity
        entityId={entityId}
        isTo={false}
        stixCoreObjectTypes={stixCoreObjectTypes}
        targetStixCyberObservableTypes={undefined}
        paddingRight={noPadding ? null : 220}
        paginationOptions={paginationOptions}
        variant={variant}
        onCreate={undefined}
      />
    )}
  </Security>
);

interface EntityStixSightingRelationshipsProps {
  isTo: boolean,
  entityId: string,
  noPadding?: boolean,
  stixCoreObjectTypes: string[],
  entityLink: string,
  disableExport?: boolean,
}

const EntityStixSightingRelationships: FunctionComponent<EntityStixSightingRelationshipsProps> = ({
  isTo,
  entityId,
  noPadding,
  stixCoreObjectTypes,
  entityLink,
  disableExport,
}) => {
  const classes = useStyles();
  const { isFeatureEnable } = useHelper();
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<EntityStixSightingRelationshipsLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      searchTerm: '',
      sortBy: 'first_seen',
      orderAsc: false,
      openExports: false,
      filters: emptyFilterGroup,
    },
  );
  const {
    sortBy,
    orderAsc,
    openExports,
    filters,
    numberOfElements,
  } = viewStorage;

  const userFilters = useRemoveIdAndIncorrectKeysFromFilterGroupObject(filters, ['stix-sighting-relationship']);

  const contextFilters: FilterGroup = {
    mode: 'and',
    filters: [
      { key: isTo ? 'toId' : 'fromId', values: [entityId], operator: 'eq' },
      {
        key: 'entity_type',
        values: ['stix-sighting-relationship'],
        operator: 'eq',
        mode: 'or',
      },
    ],
    filterGroups: userFilters && isFilterGroupNotEmpty(userFilters) ? [userFilters] : [],
  };
  const finalPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as EntityStixSightingRelationshipsLinesPaginationQuery$variables;

  const queryRef = useQueryLoading<EntityStixSightingRelationshipsLinesPaginationQuery>(
    entityStixSightingRelationshipsLinesQuery,
    finalPaginationOptions,
  );

  const FABReplaced = isFeatureEnable('FAB_REPLACEMENT');

  const renderLines = () => {
    const dataColumns = {
      x_opencti_negative: {
        label: 'Status',
        width: '10%',
        isSortable: true,
      },
      attribute_count: {
        label: 'Count',
        width: '10%',
        isSortable: true,
      },
      name: {
        label: 'Name',
        width: '20%',
        isSortable: false,
      },
      entity_type: {
        label: 'Entity type',
        width: '15%',
        isSortable: false,
      },
      first_seen: {
        label: 'First obs.',
        width: '15%',
        isSortable: true,
      },
      last_seen: {
        label: 'Last obs.',
        width: '15%',
        isSortable: true,
      },
      confidence: {
        label: 'Confidence level',
        isSortable: true,
      },
    };
    return (
      <>
        <ListLines
          helpers={helpers}
          sortBy={sortBy}
          orderAsc={orderAsc}
          dataColumns={dataColumns}
          handleSort={helpers.handleSort}
          handleSearch={helpers.handleSearch}
          handleAddFilter={helpers.handleAddFilter}
          handleRemoveFilter={helpers.handleRemoveFilter}
          handleSwitchGlobalMode={helpers.handleSwitchGlobalMode}
          handleSwitchLocalMode={helpers.handleSwitchLocalMode}
          handleToggleExports={disableExport ? null : helpers.handleToggleExports}
          filters={filters}
          availableFilterKeys={[
            'toTypes',
            'objectLabel',
            'objectMarking',
            'workflow_id',
            'created',
            'createdBy',
            'x_opencti_negative',
          ]}
          openExports={openExports}
          exportContext={{ entity_type: 'stix-sighting-relationship', entity_id: entityId }}
          availableEntityTypes={stixCoreObjectTypes}
          displayImport={true}
          secondaryAction={true}
          paginationOptions={finalPaginationOptions}
          numberOfElements={numberOfElements}
          createButton={FABReplaced && <SightingCreationComponent
            isTo={isTo}
            entityId={entityId}
            noPadding={noPadding}
            paginationOptions={finalPaginationOptions}
            stixCoreObjectTypes={stixCoreObjectTypes}
            variant='controlledDial'
                                       />}
        >
          {queryRef && (
          <React.Suspense
            fallback={
              <>
                {Array(20)
                  .fill(0)
                  .map((_, idx) => (
                    <EntityStixSightingRelationshipLineDummy key={idx} dataColumns={dataColumns} />
                  ))}
              </>
            }
          >
            <EntityStixSightingRelationshipsLines
              queryRef={queryRef}
              paginationOptions={finalPaginationOptions}
              entityLink={entityLink}
              dataColumns={dataColumns}
              isTo={isTo}
              setNumberOfElements={helpers.handleSetNumberOfElements}
              onLabelClick={helpers.handleAddFilter}
            />
          </React.Suspense>
          )}
        </ListLines>
      </>
    );
  };

  return (
    <div className={classes.container}>
      {renderLines()}
      {!FABReplaced
        && <SightingCreationComponent
          isTo={isTo}
          entityId={entityId}
          noPadding={noPadding}
          paginationOptions={finalPaginationOptions}
          stixCoreObjectTypes={stixCoreObjectTypes}
           />
      }
    </div>
  );
};

export default EntityStixSightingRelationships;
