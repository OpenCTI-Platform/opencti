import { Button } from '@mui/material';
import React, { FunctionComponent, useEffect, useState } from 'react';
import { useFormatter } from '../../../../components/i18n';
import Drawer from '../drawer/Drawer';
import { stixCoreRelationshipCreationFromEntityQuery, TargetEntity } from './StixCoreRelationshipCreationFromEntity';
import { useBuildEntityTypeBasedFilterContext } from '../../../../utils/filters/filtersUtils';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import { StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery$variables } from './__generated__/StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery.graphql';
import { PaginationOptions } from '../../../../components/list_lines'; import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { StixCoreRelationshipCreationFromEntityQuery } from './__generated__/StixCoreRelationshipCreationFromEntityQuery.graphql';
import StixCoreRelationshipCreationHeaderButtons from './StixCoreRelationshipCreationHeaderButtons';
import StixCoreRelationshipCreationSelectEntityStage from './StixCoreRelationshipCreationSelectEntityStage';
import StixCoreRelationshipCreationFormStage from './StixCoreRelationshipCreationFormStage';

interface StixCoreRelationshipCreationFromEntityHeaderProps {
  entityId: string;
  targetStixDomainObjectTypes?: string[];
  targetStixCyberObservableTypes?: string[];
  allowedRelationshipTypes?: string[];
  targetEntities?: TargetEntity[];
  isRelationReversed?: boolean;
  handleReverseRelation?: () => void;
  defaultStartTime?: string;
  defaultStopTime?: string;
  paginationOptions: Record<string, unknown>;
  connectionKey?: string;
  onCreate?: () => void;
}

const StixCoreRelationshipCreationFromEntityHeader: FunctionComponent<
StixCoreRelationshipCreationFromEntityHeaderProps
> = ({
  entityId,
  targetStixDomainObjectTypes = [],
  targetStixCyberObservableTypes = [],
  allowedRelationshipTypes,
  targetEntities: initialTargetEntities = [],
  isRelationReversed,
  handleReverseRelation = undefined,
  defaultStartTime = (new Date()).toISOString(),
  defaultStopTime = (new Date()).toISOString(),
  paginationOptions,
  connectionKey,
  onCreate,
}) => {
  const { t_i18n } = useFormatter();
  const [open, setOpen] = useState<boolean>(false);
  const [step, setStep] = useState<number>(0);
  const [targetEntities, setTargetEntities] = useState<TargetEntity[]>(
    initialTargetEntities,
  );

  const handleOpen = () => setOpen(true);
  const handleClose = () => {
    setOpen(false);
    setStep(0);
    setTargetEntities([]);
  };
  const handleResetSelection = () => {
    setStep(0);
    setTargetEntities([]);
  };

  const storageKey = `stixCoreRelationshipCreationFromEntity-${entityId}-${targetStixDomainObjectTypes.join('-')}-${targetStixCyberObservableTypes.join('-')}`;

  const [sortBy, setSortBy] = useState('_score');
  const [orderAsc, setOrderAsc] = useState(false);
  const { viewStorage, helpers } = usePaginationLocalStorage<StixCoreRelationshipCreationFromEntityStixCoreObjectsLinesQuery$variables>(
    storageKey,
    {},
    true,
  );
  const { searchTerm = '', orderAsc: storageOrderAsc, sortBy: storageSortBy, filters } = viewStorage;
  useEffect(() => {
    if (storageSortBy && (storageSortBy !== sortBy)) setSortBy(storageSortBy);
    if (storageOrderAsc !== undefined && (storageOrderAsc !== orderAsc)) setOrderAsc(storageOrderAsc);
  }, [storageOrderAsc, storageSortBy]);
  const virtualEntityTypes = ['Stix-Domain-Object', 'Stix-Cyber-Observable'];
  const contextFilters = useBuildEntityTypeBasedFilterContext(virtualEntityTypes, filters);
  const searchPaginationOptions: PaginationOptions = {
    search: searchTerm,
    filters: contextFilters,
    orderBy: sortBy,
    orderMode: orderAsc ? 'asc' : 'desc',
  } as PaginationOptions;

  const queryRef = useQueryLoading<
  StixCoreRelationshipCreationFromEntityQuery
  >(
    stixCoreRelationshipCreationFromEntityQuery,
    { id: entityId },
  );

  if (!queryRef) return <Loader variant={LoaderVariant.inElement} />;

  return (
    <>
      <Button
        onClick={handleOpen}
        variant='outlined'
        style={{ marginLeft: '6px' }}
      >
        {t_i18n('Create Relationship')}
      </Button>
      <Drawer
        title={t_i18n('Create a relationship')}
        open={open}
        onClose={handleClose}
        header={(
          <StixCoreRelationshipCreationHeaderButtons
            show={step < 1}
            showSDOs={targetStixDomainObjectTypes.length > 0}
            showSCOs={targetStixCyberObservableTypes.length > 0}
            searchTerm={searchTerm}
            searchPaginationOptions={searchPaginationOptions}
            actualTypeFilterValues={[
              ...targetStixDomainObjectTypes,
              ...targetStixCyberObservableTypes,
            ]}
          />
        )}
      >
        {step === 0
          ? (
            <StixCoreRelationshipCreationSelectEntityStage
              handleNextStep={() => setStep(1)}
              storageKey={storageKey}
              entityId={entityId}
              queryRef={queryRef}
              targetStixDomainObjectTypes={targetStixDomainObjectTypes}
              targetStixCyberObservableTypes={targetStixCyberObservableTypes}
              allowedRelationshipTypes={allowedRelationshipTypes}
              targetEntities={targetEntities}
              setTargetEntities={setTargetEntities}
              searchPaginationOptions={searchPaginationOptions}
              helpers={helpers}
              contextFilters={contextFilters}
              virtualEntityTypes={virtualEntityTypes}
            />
          ) : (
            <StixCoreRelationshipCreationFormStage
              targetEntities={targetEntities}
              queryRef={queryRef}
              isRelationReversed={isRelationReversed}
              allowedRelationshipTypes={allowedRelationshipTypes}
              handleReverseRelation={handleReverseRelation}
              handleResetSelection={handleResetSelection}
              handleClose={handleClose}
              defaultStartTime={defaultStartTime}
              defaultStopTime={defaultStopTime}
              helpers={helpers}
              entityId={entityId}
              paginationOptions={paginationOptions}
              connectionKey={connectionKey}
              onCreate={onCreate}
            />
          )
        }
      </Drawer>
    </>
  );
};

export default StixCoreRelationshipCreationFromEntityHeader;
