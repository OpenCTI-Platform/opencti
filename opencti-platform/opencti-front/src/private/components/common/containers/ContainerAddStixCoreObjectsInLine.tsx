import { IconButton, Tooltip, Typography } from '@mui/material';
import React, { FunctionComponent, Suspense, useState } from 'react';
import { PreloadedQuery, usePreloadedQuery } from 'react-relay';
import Button from '@common/button/Button';
import { Add } from '@mui/icons-material';
import { useTheme } from '@mui/styles';
import { useFormatter } from '../../../../components/i18n';
import Drawer from '../drawer/Drawer';
import StixDomainObjectCreation from '../stix_domain_objects/StixDomainObjectCreation';
import ListLines from '../../../../components/list_lines/ListLines';
import { PaginationLocalStorage, usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import { emptyFilterGroup } from '../../../../utils/filters/filtersUtils';
import useAuth from '../../../../utils/hooks/useAuth';
import { removeEmptyFields } from '../../../../utils/utils';
import { ContainerAddStixCoreObjectsLinesQuery, ContainerAddStixCoreObjectsLinesQuery$variables } from './__generated__/ContainerAddStixCoreObjectsLinesQuery.graphql';
import ContainerAddStixCoreObjectsLines, { containerAddStixCoreObjectsLinesQuery } from './ContainerAddStixCoreObjectsLines';
import { ContainerStixDomainObjectsLinesQuery$variables } from './__generated__/ContainerStixDomainObjectsLinesQuery.graphql';
import { ContainerStixCyberObservablesLinesQuery$variables } from './__generated__/ContainerStixCyberObservablesLinesQuery.graphql';
import StixCyberObservableCreation from '../../observations/stix_cyber_observables/StixCyberObservableCreation';
import type { Theme } from '../../../../components/Theme';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { DataColumns } from '../../../../components/list_lines';

interface ControlledDialProps {
  onOpen: () => void;
  title: string;
}

const ControlledDial = ({ onOpen, title }: ControlledDialProps) => {
  const theme = useTheme<Theme>();
  return (
    <Button
      style={{ marginLeft: theme.spacing(0.5) }}
      aria-label={title}
      size="small"
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
        color="primary"
        aria-label={t_i18n('Add')}
        onClick={() => onOpen()}
      >
        <Add />
      </IconButton>
    </Tooltip>
  );
};

type scoEdge = {
  types: string[];
  node: {
    id: string;
  };
};

interface ContainerAddStixCreObjectsInLineLoaderProps {
  queryRef: PreloadedQuery<ContainerAddStixCoreObjectsLinesQuery>;
  containerId: string;
  buildColumns: () => DataColumns;
  linesPaginationOptions: ContainerStixDomainObjectsLinesQuery$variables | ContainerStixCyberObservablesLinesQuery$variables;
  knowledgeGraph?: boolean;
  selectedElements: unknown[];
  handleSelect: (o: { id: string }) => void;
  handleDeselect: (o: { id: string }) => void;
  helpers: PaginationLocalStorage['helpers'];
  containerRef: HTMLInputElement;
  enableReferences?: boolean;
}

const ContainerAddStixCreObjectsInLineLoader: FunctionComponent<ContainerAddStixCreObjectsInLineLoaderProps> = ({
  queryRef,
  containerId,
  buildColumns,
  linesPaginationOptions,
  knowledgeGraph,
  selectedElements,
  handleSelect,
  handleDeselect,
  helpers,
  containerRef,
  enableReferences,
}) => {
  const data = usePreloadedQuery(containerAddStixCoreObjectsLinesQuery, queryRef);
  return (
    <ContainerAddStixCoreObjectsLines
      data={data}
      containerId={containerId}
      paginationOptions={linesPaginationOptions}
      dataColumns={buildColumns()}
      initialLoading={data === null}
      knowledgeGraph={knowledgeGraph}
      containerStixCoreObjects={selectedElements}
      onAdd={handleSelect}
      onDelete={handleDeselect}
      setNumberOfElements={helpers.handleSetNumberOfElements}
      containerRef={{ current: containerRef }}
      enableReferences={enableReferences}
      onLabelClick={helpers.handleAddFilter}
    />
  );
};

interface ContainerAddStixCoreObjectsInLineProps {
  containerId: string;
  targetStixCoreObjectTypes: string[];
  paginationOptions: ContainerStixDomainObjectsLinesQuery$variables | ContainerStixCyberObservablesLinesQuery$variables;
  containerStixCoreObjects: unknown[];
  onAdd?: (node: { id: string }) => void;
  onDelete?: (node: { id: string }) => void;
  confidence?: number;
  defaultCreatedBy?: unknown;
  defaultMarkingDefinitions?: unknown[];
  selectedText?: string;
  enableReferences?: boolean | undefined;
  knowledgeGraph?: boolean | undefined;
}

const ContainerAddStixCoreObjectsInLine: FunctionComponent<ContainerAddStixCoreObjectsInLineProps> = ({
  containerId,
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
    numberOfElements,
  } = viewStorage;
  const [containerRef, setRef] = useState<HTMLInputElement>();
  const [selectedElements, setSelectedElements] = useState<scoEdge[]>(containerStixCoreObjects as scoEdge[]);
  const handleSelect = (node: { id: string }) => {
    setSelectedElements([
      ...selectedElements,
      { node, types: ['manual'] },
    ]);
    if (typeof onAdd === 'function') onAdd(node);
  };
  const handleDeselect = (node: { id: string }) => {
    setSelectedElements(selectedElements.filter((e) => e.node.id !== node.id));
    if (typeof onDelete === 'function') onDelete(node);
  };
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

  const Header = () => {
    const [openCreateEntity, setOpenCreateEntity] = useState<boolean>(false);
    const [openCreateObservable, setOpenCreateObservable] = useState<boolean>(false);
    return (
      <>
        <div
          style={{
            width: '100%',
            display: 'flex',
            flexDirection: 'row',
            justifyContent: 'space-between',
            alignItems: 'center',
          }}
        >
          <Typography variant="subtitle2">
            {showSDOCreation ? t_i18n('Add entities') : t_i18n('Add observables')}
          </Typography>
          <div style={{ marginRight: '10px' }}>
            {showSDOCreation && (
              <Button
                disableElevation
                size="small"
                aria-label={t_i18n('Create an entity')}
                onClick={() => setOpenCreateEntity(true)}
              >
                {t_i18n('Create an entity')}
              </Button>
            )}
            {showSCOCreation && (
              <Button
                style={{ fontSize: 'small', marginLeft: '3px' }}
                disableElevation
                size="small"
                aria-label={t_i18n('Create an observable')}
                onClick={() => setOpenCreateObservable(true)}
              >
                {t_i18n('Create an observable')}
              </Button>
            )}
          </div>
        </div>
        <StixDomainObjectCreation
          display={true}
          inputValue=""
          speeddial={true}
          open={openCreateEntity}
          handleClose={() => setOpenCreateEntity(false)}
          creationCallback={undefined}
          onCompleted={undefined}
          isFromBulkRelation={undefined}
          confidence={confidence}
          defaultCreatedBy={defaultCreatedBy}
          defaultMarkingDefinitions={defaultMarkingDefinitions}
          stixDomainObjectTypes={targetStixCoreObjectTypes}
          paginationKey="Pagination_stixCoreObjects"
          paginationOptions={searchPaginationOptions}
        />
        <StixCyberObservableCreation
          display={true}
          contextual={true}
          inputValue=""
          paginationKey="Pagination_stixCoreObjects"
          paginationOptions={searchPaginationOptions}
          speeddial={true}
          open={openCreateObservable}
          handleClose={() => setOpenCreateObservable(false)}
          type={undefined}
          defaultCreatedBy={undefined}
        />
      </>
    );
  };

  const Dial = showSDOCreation
    ? ({ onOpen }: { onOpen: () => void }) => <ControlledDial title={t_i18n('Add entity')} onOpen={onOpen} />
    : ({ onOpen }: { onOpen: () => void }) => <ControlledDial title={t_i18n('Add observable')} onOpen={onOpen} />;

  return (
    <Drawer
      title="" // Defined in custom header prop
      controlledDial={knowledgeGraph ? GraphControlledDial : Dial}
      header={<Header />}
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
        numberOfElements={numberOfElements}
        iconExtension={true}
        parametersWithPadding={true}
        disableExport={true}
        availableEntityTypes={targetStixCoreObjectTypes}
        entityTypes={targetStixCoreObjectTypes}
      >
        {(containerRef && queryRef) && (
          <Suspense>
            <ContainerAddStixCreObjectsInLineLoader
              queryRef={queryRef}
              containerId={containerId}
              buildColumns={buildColumns}
              linesPaginationOptions={linesPaginationOptions}
              knowledgeGraph={knowledgeGraph}
              selectedElements={selectedElements}
              handleSelect={handleSelect}
              handleDeselect={handleDeselect}
              helpers={helpers}
              containerRef={containerRef}
              enableReferences={enableReferences}
            />
          </Suspense>
        )}
      </ListLines>
    </Drawer>
  );
};

export default ContainerAddStixCoreObjectsInLine;
