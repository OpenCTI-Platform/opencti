import React from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import makeStyles from '@mui/styles/makeStyles';
import StixCoreRelationshipCreationFromEntity from './StixCoreRelationshipCreationFromEntity';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import {
  convertFilters,
} from '../../../../utils/ListParameters';
import ExportContextProvider from '../../../../utils/ExportContextProvider';
import EntityStixCoreRelationshipsRelationshipsView from './EntityStixCoreRelationshipsRelationshipsView';
import EntityStixCoreRelationshipsEntitiesView from './EntityStixCoreRelationshipsEntitiesView';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';

const useStyles = makeStyles(() => ({
  container: {
    marginTop: 15,
    paddingBottom: 70,
  },
}));

const EntityStixCoreRelationships = ({
  stixCoreObjectTypes,
  entityId,
  role,
  entityLink,
  disableExport,
  enableNestedView,
  relationshipTypes,
  isRelationReversed,
  allDirections,
  defaultStartTime,
  defaultStopTime,
  currentView,
  paddingRightButtonAdd,
}) => {
  const classes = useStyles();
  const localStorage = usePaginationLocalStorage(
    `view-relationships-${entityId}-${stixCoreObjectTypes?.join(
      '-',
    )}-${relationshipTypes?.join('-')}`,
    {
      searchTerm: '',
      sortBy: 'created',
      orderAsc: false,
      openExports: false,
      filters: {},
      view: 'entities',
    },
  );
  const { paginationOptions } = localStorage;
  const {
    view,
  } = localStorage.viewStorage;

  const finalView = currentView || view;

  const finalStixCoreObjectTypes = stixCoreObjectTypes || [
    'Stix-Core-Object',
  ];
  const paddingRight = paddingRightButtonAdd ?? 220;
  const targetStixCyberObservableTypes = finalStixCoreObjectTypes.includes('Stix-Core-Object')
      || finalStixCoreObjectTypes.includes('Stix-Cyber-Observable')
    ? ['Stix-Cyber-Observable']
    : null;
  const stixCoreObjectTypesWithoutObservables = finalStixCoreObjectTypes.filter((n) => n !== 'Stix-Cyber-Observable');
  const targetStixDomainObjectTypes = stixCoreObjectTypesWithoutObservables.includes('Stix-Core-Object')
    ? ['Stix-Domain-Object']
    : stixCoreObjectTypesWithoutObservables;
  return (
      <ExportContextProvider>
        <div className={classes.container}>
          {finalView === 'entities'
            && <EntityStixCoreRelationshipsEntitiesView
              localStorage={localStorage}
              entityId={entityId}
              role={role}
              stixCoreObjectTypes={stixCoreObjectTypes}
              relationshipTypes={relationshipTypes}
              entityLink={entityLink}
              isRelationReversed={isRelationReversed}
              disableExport={disableExport}
              currentView={currentView}
              enableNestedView={enableNestedView}
            />}
           {finalView === 'relationships'
            && <EntityStixCoreRelationshipsRelationshipsView
            localStorage={localStorage}
            entityId={entityId}
            role={role}
            stixCoreObjectTypes={stixCoreObjectTypes}
            relationshipTypes={relationshipTypes}
            entityLink={entityLink}
            isRelationReversed={isRelationReversed}
            allDirections={allDirections}
            disableExport={disableExport}
            currentView={currentView}
            enableNestedView={enableNestedView}
            />}
          <Security needs={[KNOWLEDGE_KNUPDATE]}>
            <StixCoreRelationshipCreationFromEntity
              entityId={entityId}
              isRelationReversed={isRelationReversed}
              paddingRight={paddingRight}
              targetStixDomainObjectTypes={targetStixDomainObjectTypes}
              targetStixCyberObservableTypes={targetStixCyberObservableTypes}
              allowedRelationshipTypes={relationshipTypes}
              paginationOptions={paginationOptions}
              defaultStartTime={defaultStartTime}
              defaultStopTime={defaultStopTime}
              connectionKey={
                finalView === 'entities'
                  ? 'Pagination_stixCoreObjects'
                  : undefined
              }
            />
          </Security>
        </div>
      </ExportContextProvider>
  );
};

EntityStixCoreRelationships.propTypes = {
  entityId: PropTypes.string,
  role: PropTypes.string,
  stixCoreObjectTypes: PropTypes.array,
  relationshipTypes: PropTypes.array,
  entityLink: PropTypes.string,
  exploreLink: PropTypes.string,
  isRelationReversed: PropTypes.bool,
  allDirections: PropTypes.bool,
  noState: PropTypes.bool,
  disableExport: PropTypes.bool,
  currentView: PropTypes.string,
  enableNestedView: PropTypes.bool,
  enableContextualView: PropTypes.bool,
  defaultStartTime: PropTypes.string,
  defaultStopTime: PropTypes.string,
  paddingRightButtonAdd: PropTypes.string,
};

export default EntityStixCoreRelationships;
