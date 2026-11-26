import Button from '@common/button/Button';
import { Add } from '@mui/icons-material';
import { Stack, Tooltip } from '@mui/material';
import { IconButton } from '@filigran/design-system';
import { FunctionComponent, Suspense, useRef, useState } from 'react';
import { useFormatter } from '../../../../components/i18n';
import ListLines from '../../../../components/list_lines/ListLines';
import { emptyFilterGroup } from '../../../../utils/filters/filtersUtils';
import useAuth from '../../../../utils/hooks/useAuth';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { removeEmptyFields } from '../../../../utils/utils';
import StixCyberObservableCreation from '../../observations/stix_cyber_observables/StixCyberObservableCreation';
import Drawer from '../drawer/Drawer';
import StixDomainObjectCreation from '../stix_domain_objects/StixDomainObjectCreation';
import { ContainerAddStixCoreObjectsLinesQuery, ContainerAddStixCoreObjectsLinesQuery$variables } from './__generated__/ContainerAddStixCoreObjectsLinesQuery.graphql';
import { ContainerStixDomainObjectsLinesQuery$variables } from './__generated__/ContainerStixDomainObjectsLinesQuery.graphql';
import ContainerAddStixCoreObjectsLines, { containerAddStixCoreObjectsLinesQuery } from './ContainerAddStixCoreObjectsLines';
import { ContainerStixCyberObservablesLinesPaginationQuery$variables } from '@components/common/containers/__generated__/ContainerStixCyberObservablesLinesPaginationQuery.graphql';
import { DefaultMarking } from '@components/settings/marking_definitions/markingDefinition.types';
import { CreationFeedbackContext } from '../../../../utils/hooks/useCreationFeedback';
import { useAddCreatedObjectsToContainer } from './useAddCreatedObjectsToContainer';
import { CreatedObject } from './useContainerObjects';

interface ControlledDialProps {
  onOpen: () => void;
  title: string;
}

const ControlledDial = ({ onOpen, title }: ControlledDialProps) => {
  return (
    <Button
      aria-label={title}
      onClick={() => onOpen()}
    >
      {title}
    </Button>
  );
};

const GraphControlledDial = ({ onOpen }: { onOpen: () => void }) => {
  const { t_i18n } = useFormatter();

  return (
    <Tooltip title={t_i18n('Add an entity to this container')}>
      <IconButton
        variant="default"
        priority="tertiary"
        aria-label={t_i18n('Add an entity to this container')}
        onClick={() => onOpen()}
        icon={<Add />}
      />
    </Tooltip>
  );
};

type scoEdge = {
  types: string[];
  node: {
    id: string;
  };
};

interface ContainerAddStixCoreObjectsInLineProps {
  containerId: string;
  // Entity type of the container, named in the confirmation message
  containerType?: string;
  // The full object for the parent view (e.g. a graph node) when an object created from the panel is added
  resolveObject?: (id: string) => Promise<CreatedObject>;
  targetStixCoreObjectTypes: string[];
  paginationOptions: ContainerStixDomainObjectsLinesQuery$variables | ContainerStixCyberObservablesLinesPaginationQuery$variables;
  containerStixCoreObjects: unknown[];
  onAdd?: (node: { id: string }) => void;
  onDelete?: (node: { id: string }) => void;
  confidence?: number;
  defaultCreatedBy?: unknown;
  defaultMarkingDefinitions?: readonly DefaultMarking[];
  selectedText?: string;
  enableReferences?: boolean | undefined;
  knowledgeGraph?: boolean | undefined;
}

const ContainerAddStixCoreObjectsInLine: FunctionComponent<ContainerAddStixCoreObjectsInLineProps> = ({
  containerId,
  containerType,
  resolveObject,
  targetStixCoreObjectTypes,
  paginationOptions: linesPaginationOptions,
  containerStixCoreObjects,
  onAdd,
  onDelete,
  confidence,
  defaultCreatedBy,
  defaultMarkingDefinitions,
  selectedText,
  enableReferences = false,
  knowledgeGraph = false,
}) => {
  const { t_i18n } = useFormatter();
  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();

  const showSDOCreation = targetStixCoreObjectTypes.includes('Stix-Domain-Object');
  const showSCOCreation = targetStixCoreObjectTypes.includes('Stix-Cyber-Observable');

  const LOCAL_STORAGE_KEY = `container-${containerId}-add-${targetStixCoreObjectTypes}`;
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<
    ContainerAddStixCoreObjectsLinesQuery$variables
  >(
    LOCAL_STORAGE_KEY,
    {
      searchTerm: '',
      sortBy: '_score',
      orderAsc: false,
      filters: emptyFilterGroup,
      types: targetStixCoreObjectTypes,
    },
    true,
  );
  const {
    sortBy,
    orderAsc,
    searchTerm,
    filters,
  } = viewStorage;
  const [containerRef, setRef] = useState<HTMLDivElement | null>(null);
  const [selectedElements, setSelectedElements] = useState<scoEdge[]>(containerStixCoreObjects as scoEdge[]);
  // Read when the objects created from the panel are added, after a delay
  const selectedElementsRef = useRef(selectedElements);
  selectedElementsRef.current = selectedElements;
  // Functional updates: several objects can be added at once
  const handleSelect = (node: { id: string }) => {
    setSelectedElements((current) => [
      ...current,
      { node, types: ['manual'] },
    ]);
    if (typeof onAdd === 'function') onAdd(node);
  };
  const handleDeselect = (node: { id: string }) => {
    setSelectedElements((current) => current.filter((e) => e.node.id !== node.id));
    if (typeof onDelete === 'function') onDelete(node);
  };
  const { onCreated, referencesDialog, bulkCreation } = useAddCreatedObjectsToContainer({
    containerId,
    containerType,
    knowledgeGraph,
    paginationOptions: linesPaginationOptions,
    enableReferences,
    isInContainer: (id) => selectedElementsRef.current.some((e) => e.node.id === id),
    onAdded: handleSelect,
    onRemoved: handleDeselect,
    resolveObject,
  });
  const keyword = (searchTerm ?? '').length === 0 ? selectedText : searchTerm;
  const buildColumns = () => {
    return {
      entity_type: {
        label: 'Type',
        width: '15%',
        isSortable: true,
      },
      value: {
        label: 'Value',
        width: '32%',
        isSortable: false,
      },
      createdBy: {
        label: 'Author',
        width: '15%',
        isSortable: isRuntimeFieldEnable(),
      },
      objectLabel: {
        label: 'Labels',
        width: '22%',
        isSortable: false,
      },
      objectMarking: {
        label: 'Marking',
        width: '15%',
        isSortable: isRuntimeFieldEnable(),
      },
    };
  };
  const { count: _, ...paginationOptionsNoCount } = paginationOptions;
  const searchPaginationOptions = removeEmptyFields({
    ...paginationOptionsNoCount,
    search: keyword,
  });
  const queryRef = useQueryLoading<ContainerAddStixCoreObjectsLinesQuery>(containerAddStixCoreObjectsLinesQuery, { count: 100, ...searchPaginationOptions });

  const [openCreateEntity, setOpenCreateEntity] = useState<boolean>(false);
  const [openCreateObservable, setOpenCreateObservable] = useState<boolean>(false);

  // An element, not a component: a component declared here would be remounted, with the open creation form, at each render
  const header = (
    <CreationFeedbackContext.Provider value={{ silenceCreationSuccess: true, bulkCreation }}>
      <StixDomainObjectCreation
        display={false}
        inputValue=""
        speeddial={true}
        open={openCreateEntity}
        handleClose={() => setOpenCreateEntity(false)}
        creationCallback={undefined}
        onCompleted={undefined}
        onCreated={onCreated}
        isFromBulkRelation={undefined}
        confidence={confidence}
        defaultCreatedBy={defaultCreatedBy}
        defaultMarkingDefinitions={defaultMarkingDefinitions}
        stixDomainObjectTypes={targetStixCoreObjectTypes}
        paginationKey="Pagination_stixCoreObjects"
        paginationOptions={searchPaginationOptions}
      />
      <StixCyberObservableCreation
        display={false}
        contextual={true}
        inputValue=""
        paginationKey="Pagination_stixCoreObjects"
        paginationOptions={searchPaginationOptions}
        speeddial={true}
        open={openCreateObservable}
        handleClose={() => setOpenCreateObservable(false)}
        type={undefined}
        defaultCreatedBy={defaultCreatedBy}
        defaultMarkingDefinitions={defaultMarkingDefinitions as unknown as []}
        onCreated={onCreated}
      />
    </CreationFeedbackContext.Provider>
  );

  const Dial = showSDOCreation
    ? ({ onOpen }: { onOpen: () => void }) => <ControlledDial title={t_i18n('Add entity')} onOpen={onOpen} />
    : ({ onOpen }: { onOpen: () => void }) => <ControlledDial title={t_i18n('Add observable')} onOpen={onOpen} />;

  const buttons = (
    <Stack
      direction="row"
      sx={{
        gap: 1,
      }}
    >
      {showSDOCreation && (
        <Button
          disableElevation
          aria-label={t_i18n('Create an entity')}
          onClick={() => setOpenCreateEntity(true)}
        >
          {t_i18n('Create an entity')}
        </Button>
      )}
      {showSCOCreation && (
        <Button
          disableElevation
          aria-label={t_i18n('Create an observable')}
          onClick={() => setOpenCreateObservable(true)}
        >
          {t_i18n('Create an observable')}
        </Button>
      )}
    </Stack>
  );

  return (
    <>
      <Drawer
        controlledDial={knowledgeGraph ? GraphControlledDial : Dial}
        header={header}
        title={showSDOCreation ? t_i18n('Add entities') : t_i18n('Add observables')}
        ref={setRef}
      >
        <ListLines
          helpers={helpers}
          sortBy={sortBy}
          orderAsc={orderAsc}
          dataColumns={buildColumns()}
          handleSearch={helpers.handleSearch}
          keyword={keyword}
          handleSort={helpers.handleSort}
          handleAddFilter={helpers.handleAddFilter}
          handleRemoveFilter={helpers.handleRemoveFilter}
          handleSwitchLocalMode={helpers.handleSwitchLocalMode}
          handleSwitchGlobalMode={helpers.handleSwitchGlobalMode}
          disableCards={true}
          filters={filters}
          paginationOptions={searchPaginationOptions}
          iconExtension={true}
          parametersWithPadding={true}
          disableExport={true}
          availableEntityTypes={targetStixCoreObjectTypes}
          entityTypes={targetStixCoreObjectTypes}
          createButton={buttons}
        >
          {(containerRef && queryRef) && (
            <Suspense>
              <ContainerAddStixCoreObjectsLines
                queryRef={queryRef}
                containerId={containerId}
                paginationOptions={linesPaginationOptions}
                dataColumns={buildColumns()}
                knowledgeGraph={knowledgeGraph}
                containerStixCoreObjects={selectedElements}
                onAdd={handleSelect}
                onDelete={handleDeselect}
                setNumberOfElements={helpers.handleSetNumberOfElements}
                enableReferences={enableReferences}
                onLabelClick={helpers.handleAddFilter}
              />
            </Suspense>
          )}
        </ListLines>
      </Drawer>
      {referencesDialog}
    </>
  );
};

export default ContainerAddStixCoreObjectsInLine;
