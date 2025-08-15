import { Button } from '@mui/material';
import React, { FunctionComponent, useContext, useEffect, useState } from 'react';
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
import { CreateRelationshipContext } from './CreateRelationshipContextProvider';
import { computeTargetStixCyberObservableTypes, computeTargetStixDomainObjectTypes } from '../../../../utils/stixTypeUtils';

/**
 * This file contains the code for the "Create Relationship" button in the top
 * right of entity pages and the associated drawer that opens.
 * This workflow is based off the StixCoreRelationshipCreationFromEntity.tsx
 * file, but attempting to move away from the floating action button and grant
 * the user more flexibility in where they can create relationships from.
 */

interface StixCoreRelationshipCreationFromEntityHeaderProps {
  entityId: string;
  targetEntities?: TargetEntity[];
  handleReverseRelation?: () => void;
  defaultStartTime?: string;
  defaultStopTime?: string;
}

const StixCoreRelationshipCreationFromEntityHeader: FunctionComponent<
StixCoreRelationshipCreationFromEntityHeaderProps
> = ({
  entityId,
  targetEntities: initialTargetEntities = [],
  defaultStartTime = (new Date()).toISOString(),
  defaultStopTime = (new Date()).toISOString(),
}) => {
  const { t_i18n } = useFormatter();

  // Fetch from context
  const { state: {
    stixCoreObjectTypes = [],
  } } = useContext(CreateRelationshipContext);

  // Compute SDOs and SCOs
  const targetStixDomainObjectTypes = computeTargetStixDomainObjectTypes(stixCoreObjectTypes);
  const targetStixCyberObservableTypes = computeTargetStixCyberObservableTypes(stixCoreObjectTypes);

  const [targetEntities, setTargetEntities] = useState<TargetEntity[]>(
    initialTargetEntities,
  );

  // Drawer and form control
  const [open, setOpen] = useState<boolean>(false);
  const [step, setStep] = useState<number>(0);
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
  const contextFilters = useBuildEntityTypeBasedFilterContext(stixCoreObjectTypes, filters);
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
      {/* The controlled dial to open the drawer */}
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
          // Create entity and/or observable buttons; only appear in first step
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
              targetEntities={targetEntities}
              setTargetEntities={setTargetEntities}
              searchPaginationOptions={searchPaginationOptions}
              helpers={helpers}
              contextFilters={contextFilters}
              virtualEntityTypes={stixCoreObjectTypes}
            />
          ) : (
            <StixCoreRelationshipCreationFormStage
              targetEntities={targetEntities}
              queryRef={queryRef}
              handleResetSelection={handleResetSelection}
              handleClose={handleClose}
              defaultStartTime={defaultStartTime}
              defaultStopTime={defaultStopTime}
              helpers={helpers}
              entityId={entityId}
            />
          )
        }
      </Drawer>
    </>
  );
};

export default StixCoreRelationshipCreationFromEntityHeader;
