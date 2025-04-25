import React, { FunctionComponent, useContext, useEffect, useState } from 'react';
import { PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { CircularProgress, Fab } from '@mui/material';
import { ChevronRightOutlined } from '@mui/icons-material';
import { StixCoreRelationshipCreationFromEntityQuery } from './__generated__/StixCoreRelationshipCreationFromEntityQuery.graphql';
import {
  stixCoreRelationshipCreationFromEntityQuery,
  stixCoreRelationshipCreationFromEntityStixCoreObjectsLineFragment,
  stixCoreRelationshipCreationFromEntityStixCoreObjectsLinesFragment,
  stixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery,
  TargetEntity,
} from './StixCoreRelationshipCreationFromEntity';
import { PaginationOptions } from '../../../../components/list_lines';
import { UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';
import { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import { useFormatter } from '../../../../components/i18n';
import useEntityToggle from '../../../../utils/hooks/useEntityToggle';
import { getMainRepresentative } from '../../../../utils/defaultRepresentatives';
import { ModuleHelper } from '../../../../utils/platformModulesHelper';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery$variables } from './__generated__/StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery.graphql';
import { UsePreloadedPaginationFragment } from '../../../../utils/hooks/usePreloadedPaginationFragment';
import {
  type StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery as StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQueryType,
} from './__generated__/StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery.graphql';
import { UserContext } from '../../../../utils/hooks/useAuth';
import DataTable from '../../../../components/dataGrid/DataTable';
import { DataTableVariant } from '../../../../components/dataGrid/dataTableTypes';
import { StixCoreRelationshipCreationFromEntityStixCoreObjectsLines_data$data } from './__generated__/StixCoreRelationshipCreationFromEntityStixCoreObjectsLines_data.graphql';
import BulkRelationDialogContainer from '../bulk/dialog/BulkRelationDialogContainer';
import { CreateRelationshipContext } from './CreateRelationshipContextProvider';
import { computeTargetStixCyberObservableTypes, computeTargetStixDomainObjectTypes } from '../../../../utils/stixTypeUtils';

interface StixCoreRelationshipCreationSelectEntityStageProps {
  handleNextStep: () => void;
  storageKey: string;
  entityId: string;
  queryRef: PreloadedQuery<
  StixCoreRelationshipCreationFromEntityQuery,
  Record<string, unknown>
  >;
  targetEntities: TargetEntity[];
  setTargetEntities: React.Dispatch<React.SetStateAction<TargetEntity[]>>;
  searchPaginationOptions: PaginationOptions;
  helpers: UseLocalStorageHelpers;
  contextFilters: FilterGroup;
  virtualEntityTypes: string[];
}

const StixCoreRelationshipCreationSelectEntityStage: FunctionComponent<
StixCoreRelationshipCreationSelectEntityStageProps
> = ({
  handleNextStep,
  storageKey,
  entityId,
  queryRef: queryRefProps,
  targetEntities,
  setTargetEntities,
  searchPaginationOptions,
  helpers,
  contextFilters,
  virtualEntityTypes,
}) => {
  const { t_i18n } = useFormatter();
  const [tableRootRef, setTableRootRef] = useState<HTMLDivElement | null>(null);
  const { stixCoreObject } = usePreloadedQuery(
    stixCoreRelationshipCreationFromEntityQuery,
    queryRefProps,
  );

  // Fetch from context
  const { state: {
    relationshipTypes: allowedRelationshipTypes,
    stixCoreObjectTypes = [],
  } } = useContext(CreateRelationshipContext);

  // Compute SDOs and SCOs
  const targetStixDomainObjectTypes = computeTargetStixDomainObjectTypes(stixCoreObjectTypes);
  const targetStixCyberObservableTypes = computeTargetStixCyberObservableTypes(stixCoreObjectTypes);

  // Handle element selection
  const { selectedElements } = useEntityToggle(storageKey);
  useEffect(() => {
    const newTargetEntities: TargetEntity[] = Object.values(selectedElements).map((item) => ({
      id: item.id,
      entity_type: item.entity_type ?? '',
      name: getMainRepresentative(item),
    }));
    setTargetEntities(newTargetEntities);
  }, [selectedElements]);

  // Column headers
  const buildColumns = (platformModuleHelpers: ModuleHelper | undefined) => {
    const isRuntimeSort = platformModuleHelpers?.isRuntimeFieldEnable();
    return {
      entity_type: {
        label: 'Type',
        percentWidth: 15,
        isSortable: true,
      },
      value: {
        label: 'Value',
        percentWidth: 35,
        isSortable: false,
      },
      createdBy: {
        label: 'Author',
        percentWidth: 15,
        isSortable: isRuntimeSort,
      },
      objectLabel: {
        label: 'Labels',
        percentWidth: 20,
        isSortable: false,
      },
      objectMarking: {
        label: 'Marking',
        percentWidth: 15,
        isSortable: isRuntimeSort,
      },
    };
  };

  const queryRef = useQueryLoading<StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQueryType>(
    stixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery,
    { ...searchPaginationOptions, count: 100 } as StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery$variables,
  );
  const preloadedPaginationProps = {
    linesQuery: stixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery,
    linesFragment: stixCoreRelationshipCreationFromEntityStixCoreObjectsLinesFragment,
    queryRef,
    nodePath: ['stixCoreObjects', 'pageInfo', 'globalCount'],
    setNumberOfElements: helpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQueryType>;

  if (!stixCoreObject || !queryRef) {
    return (
      <div style={{ display: 'table', height: '100%', width: '100%' }}>
        <span
          style={{
            display: 'table-cell',
            verticalAlign: 'middle',
            textAlign: 'center',
          }}
        >
          <CircularProgress size={80} thickness={2} />
        </span>
      </div>
    );
  }

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        height: '100%',
      }}
    >
      <div style={{ height: '100%' }} ref={setTableRootRef}>
        <UserContext.Consumer>
          {({ platformModuleHelpers }) => (
            <DataTable
              disableToolBar
              disableSelectAll
              disableNavigation
              selectOnLineClick
              variant={DataTableVariant.inline}
              rootRef={tableRootRef ?? undefined}
              dataColumns={buildColumns(platformModuleHelpers)}
              resolvePath={(data: StixCoreRelationshipCreationFromEntityStixCoreObjectsLines_data$data) => data.stixCoreObjects?.edges?.map((n) => n?.node)}
              storageKey={storageKey}
              lineFragment={stixCoreRelationshipCreationFromEntityStixCoreObjectsLineFragment}
              initialValues={{}}
              toolbarFilters={contextFilters}
              preloadedPaginationProps={preloadedPaginationProps}
              entityTypes={virtualEntityTypes}
              availableEntityTypes={virtualEntityTypes}
              additionalHeaderButtons={[(
                <BulkRelationDialogContainer
                  targetObjectTypes={[...targetStixDomainObjectTypes, ...targetStixCyberObservableTypes]}
                  paginationOptions={searchPaginationOptions}
                  paginationKey="Pagination_stixCoreObjects"
                  key="BulkRelationDialogContainer"
                  stixDomainObjectId={entityId}
                  stixDomainObjectName={stixCoreObject.name ?? ''}
                  stixDomainObjectType={stixCoreObject.entity_type}
                  defaultRelationshipType={allowedRelationshipTypes?.[0]}
                  selectedEntities={targetEntities}
                />
              )]}
            />
          )}
        </UserContext.Consumer>
      </div>
      <Fab
        variant="extended"
        size="small"
        color="primary"
        onClick={handleNextStep}
        disabled={targetEntities.length < 1}
        style={{
          position: 'fixed',
          bottom: 40,
          right: 30,
          zIndex: 1001,
        }}
      >
        {t_i18n('Continue')}
        <ChevronRightOutlined />
      </Fab>
    </div>
  );
};

export default StixCoreRelationshipCreationSelectEntityStage;
