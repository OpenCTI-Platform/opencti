import React from 'react';
import useAuth from '../../../../utils/hooks/useAuth';
import CreateRelationshipControlledDial from '../../common/menus/CreateRelationshipControlledDial';
import { QueryRenderer } from '../../../../relay/environment';
import ListLines from '../../../../components/list_lines/ListLines';
import IndicatorEntitiesLines, { indicatorEntitiesLinesQuery } from './IndicatorEntitiesLines';
import StixCoreRelationshipCreationFromEntity from '../../common/stix_core_relationships/StixCoreRelationshipCreationFromEntity';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import { emptyFilterGroup } from '../../../../utils/filters/filtersUtils';

const IndicatorEntities = ({ indicatorId, relationshipType, defaultStartTime, defaultStopTime }) => {
  const LOCAL_STORAGE_KEY = 'indicator-entities';

  const { viewStorage, helpers, paginationOptions: rawPaginationOptions } = usePaginationLocalStorage(
    LOCAL_STORAGE_KEY,
    {
      searchTerm: '',
      sortBy: 'created_at',
      orderAsc: false,
      openExports: false,
      filters: emptyFilterGroup,
      numberOfElements: {
        number: 0,
        symbol: '',
      },
    },
  );

  const {
    sortBy,
    orderAsc,
    filters,
  } = viewStorage;
  const paginationOptions = {
    ...rawPaginationOptions,
    fromId: indicatorId,
    relationship_type: relationshipType || 'stix-core-relationship',
  };

  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();

  const renderLines = () => {
    const link = `/dashboard/observations/indicators/${indicatorId}/knowledge`;
    const dataColumns = {
      relationship_type: {
        label: 'Relationship type',
        width: '10%',
        isSortable: true,
      },
      entity_type: {
        label: 'Target type',
        width: '12%',
        isSortable: false,
      },
      name: {
        label: 'Name',
        width: '25%',
        isSortable: false,
      },
      createdBy: {
        label: 'Author',
        width: '12%',
        isSortable: isRuntimeFieldEnable(),
      },
      creator: {
        label: 'Creators',
        width: '12%',
        isSortable: isRuntimeFieldEnable(),
      },
      start_time: {
        label: 'First obs.',
        width: '10%',
        isSortable: true,
      },
      stop_time: {
        label: 'Last obs.',
        width: '10%',
        isSortable: true,
      },
      confidence: {
        label: 'Confidence',
        isSortable: true,
      },
    };
    return (
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
        displayImport={true}
        secondaryAction={true}
        noBottomPadding={true}
        filters={filters}
        paginationOptions={paginationOptions}
        entityTypes={['stix-core-relationship']}
        createButton={<Security needs={[KNOWLEDGE_KNUPDATE]}>
          <StixCoreRelationshipCreationFromEntity
            paginationOptions={paginationOptions}
            entityId={indicatorId}
            isRelationReversed={false}
            targetStixDomainObjectTypes={[
              'Threat-Actor',
              'Intrusion-Set',
              'Campaign',
              'Incident',
              'Malware',
              'Infrastructure',
              'Tool',
              'Vulnerability',
              'Attack-Pattern',
              'Indicator',
            ]}
            defaultStartTime={defaultStartTime}
            defaultStopTime={defaultStopTime}
            controlledDial={CreateRelationshipControlledDial}
          />
        </Security>}
      >
        <QueryRenderer
          query={indicatorEntitiesLinesQuery}
          variables={{ count: 25, ...paginationOptions }}
          render={({ props }) => (
            <IndicatorEntitiesLines
              data={props}
              paginationOptions={paginationOptions}
              dataColumns={dataColumns}
              initialLoading={props === null}
              entityId={indicatorId}
              displayRelation={true}
              entityLink={link}
            />
          )}
        />
      </ListLines>
    );
  };

  return (
    <>
      {renderLines()}
      <Security needs={[KNOWLEDGE_KNUPDATE]}>
        <StixCoreRelationshipCreationFromEntity
          paginationOptions={paginationOptions}
          entityId={indicatorId}
          isRelationReversed={false}
          targetStixDomainObjectTypes={[
            'Threat-Actor',
            'Intrusion-Set',
            'Campaign',
            'Incident',
            'Malware',
            'Infrastructure',
            'Tool',
            'Vulnerability',
            'Attack-Pattern',
            'Indicator',
          ]}
          defaultStartTime={defaultStartTime}
          defaultStopTime={defaultStopTime}
        />
      </Security>
    </>
  );
};

export default IndicatorEntities;
