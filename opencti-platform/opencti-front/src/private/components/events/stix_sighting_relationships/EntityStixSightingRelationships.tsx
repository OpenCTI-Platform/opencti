import React, { FunctionComponent } from 'react';
import {
  EntityStixSightingRelationshipsLinesPaginationQuery,
  EntityStixSightingRelationshipsLinesPaginationQuery$variables,
} from '@components/events/stix_sighting_relationships/__generated__/EntityStixSightingRelationshipsLinesPaginationQuery.graphql';
import makeStyles from '@mui/styles/makeStyles';
import {
  EntityStixSightingRelationshipLineDummy,
} from '@components/events/stix_sighting_relationships/EntityStixSightingRelationshipLine';
import ListLines from '../../../../components/list_lines/ListLines';
import EntityStixSightingRelationshipsLines, {
  entityStixSightingRelationshipsLinesQuery,
} from './EntityStixSightingRelationshipsLines';
import StixSightingRelationshipCreationFromEntity from './StixSightingRelationshipCreationFromEntity';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import { Filters } from '../../../../components/list_lines';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';

export const LOCAL_STORAGE_KEY = 'view-sightings';

const useStyles = makeStyles(() => ({
  container: {
    marginTop: 15,
    paddingBottom: 70,
  },
}));

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
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<EntityStixSightingRelationshipsLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      searchTerm: '',
      sortBy: 'first_seen',
      orderAsc: false,
      openExports: false,
      filters: {} as Filters,
    },
  );
  const {
    sortBy,
    orderAsc,
    openExports,
    filters,
    numberOfElements,
  } = viewStorage;
  const finalPaginationOptions = paginationOptions;
  if (isTo) {
    finalPaginationOptions.toId = entityId;
  } else {
    finalPaginationOptions.fromId = entityId;
  }
  const queryRef = useQueryLoading<EntityStixSightingRelationshipsLinesPaginationQuery>(
    entityStixSightingRelationshipsLinesQuery,
    finalPaginationOptions,
  );

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
        sortBy={sortBy}
        orderAsc={orderAsc}
        dataColumns={dataColumns}
        handleSort={helpers.handleSort}
        handleSearch={helpers.handleSearch}
        handleAddFilter={helpers.handleAddFilter}
        handleRemoveFilter={helpers.handleRemoveFilter}
        handleToggleExports={disableExport ? null : helpers.handleToggleExports}
        filters={filters}
        availableFilterKeys={[
          'toTypes',
          'labelledBy',
          'markedBy',
          'x_opencti_workflow_id',
          'created_start_date',
          'created_end_date',
          'createdBy',
          'x_opencti_negative',
        ]}
        openExports={openExports}
        exportEntityType="stix-sighting-relationship"
        availableEntityTypes={stixCoreObjectTypes}
        displayImport={true}
        secondaryAction={true}
        paginationOptions={finalPaginationOptions}
        numberOfElements={numberOfElements}
      >
        {queryRef && (
          <React.Suspense
            fallback={
              <>
                {Array(20)
                  .fill(0)
                  .map((idx) => (
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
              paginationOptions={finalPaginationOptions}
              variant={undefined}
              stixCoreObject={undefined}
              onCreate={undefined}
            />
          ) : (
            <StixSightingRelationshipCreationFromEntity
              entityId={entityId}
              isTo={false}
              stixCoreObjectTypes={stixCoreObjectTypes}
              targetStixCyberObservableTypes={undefined}
              paddingRight={noPadding ? null : 220}
              paginationOptions={finalPaginationOptions}
              variant={undefined}
              stixCoreObject={undefined}
              onCreate={undefined}
            />
          )}
        </Security>
      </div>
  );
};

export default EntityStixSightingRelationships;
