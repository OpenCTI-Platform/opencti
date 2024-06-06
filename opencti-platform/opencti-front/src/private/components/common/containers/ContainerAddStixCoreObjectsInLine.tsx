import { Button, Typography } from '@mui/material';
import React, { FunctionComponent, useRef, useState } from 'react';
import { useLazyLoadQuery } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import Drawer from '../drawer/Drawer';
import StixDomainObjectCreation from '../stix_domain_objects/StixDomainObjectCreation';
import ListLines from '../../../../components/list_lines/ListLines';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import { emptyFilterGroup } from '../../../../utils/filters/filtersUtils';
import useAuth from '../../../../utils/hooks/useAuth';
import { removeEmptyFields } from '../../../../utils/utils';
import { ContainerAddStixCoreObjectsLinesQuery, ContainerAddStixCoreObjectsLinesQuery$variables } from './__generated__/ContainerAddStixCoreObjectsLinesQuery.graphql';
import ContainerAddStixCoreObjectsLines, { containerAddStixCoreObjectsLinesQuery } from './ContainerAddStixCoreObjectsLines';
import { ContainerStixDomainObjectsLinesQuery$variables } from './__generated__/ContainerStixDomainObjectsLinesQuery.graphql';

const ControlledDial = ({ onOpen }: { onOpen: () => void }) => {
  const { t_i18n } = useFormatter();
  return (
    <Button
      variant="contained"
      style={{
        marginLeft: '3px',
      }}
      onClick={() => onOpen()}
    >
      {t_i18n('Add Entity')}
    </Button>
  );
};

type scoEdge = {
  types: string[],
  node: {
    id: string,
  }
};

interface ContainerAddStixCoreObjectsInLineProps {
  containerId: string,
  targetStixCoreObjectTypes: string[],
  paginationOptions: ContainerStixDomainObjectsLinesQuery$variables,
  containerStixCoreObjects: unknown[],
  selectedText?: string,
  enableReferences?: boolean,
}

const ContainerAddStixCoreObjectsInLine: FunctionComponent<
ContainerAddStixCoreObjectsInLineProps
> = ({
  containerId,
  targetStixCoreObjectTypes,
  paginationOptions: linesPaginationOptions,
  containerStixCoreObjects,
  selectedText,
  enableReferences,
}) => {
  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();
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
  const containerRef = useRef(null);
  const [selectedElements, setSelectedElements] = useState<scoEdge[]>(containerStixCoreObjects as scoEdge[]);
  const handleSelect = (node: { id: string }) => {
    setSelectedElements([
      ...selectedElements,
      { node, types: ['manual'] },
    ]);
  };
  const handleDeselect = (node: { id: string }) => {
    setSelectedElements(selectedElements.filter((e) => e.node.id !== node.id));
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
  const data = useLazyLoadQuery<ContainerAddStixCoreObjectsLinesQuery>(
    containerAddStixCoreObjectsLinesQuery,
    { count: 100, ...searchPaginationOptions },
  );

  const Header = () => {
    const { t_i18n } = useFormatter();
    const [open, setOpen] = useState<boolean>(false);
    return (<>
      <div
        style={{
          width: '100%',
          display: 'flex',
          flexDirection: 'row',
          justifyContent: 'space-between',
          alignItems: 'center',
        }}
      >
        <Typography variant='subtitle2'>{t_i18n('Add entities')}</Typography>
        <Button
          style={{
            marginRight: '5px',
            fontSize: 'small',
          }}
          variant='contained'
          disableElevation
          size='small'
          aria-label={t_i18n('Create an entity')}
          onClick={() => setOpen(true)}
        >{t_i18n('Create an entity')}</Button>
      </div>
      <StixDomainObjectCreation
        display={true}
        inputValue={''}
        speeddial={true}
        open={open}
        handleClose={() => setOpen(false)}
        creationCallback={undefined}
        confidence={undefined}
        defaultCreatedBy={undefined}
        defaultMarkingDefinitions={undefined}
        stixDomainObjectTypes={targetStixCoreObjectTypes}
        paginationKey={'Pagination_stixCoreObjects'}
        paginationOptions={searchPaginationOptions}
      />
    </>);
  };

  return (
    <Drawer
      title={''} // Defined in custom header prop
      controlledDial={ControlledDial}
      header={<Header />}
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
        <ContainerAddStixCoreObjectsLines
          data={data}
          containerId={containerId}
          paginationOptions={linesPaginationOptions}
          dataColumns={buildColumns()}
          initialLoading={data === null}
          containerStixCoreObjects={selectedElements}
          onAdd={handleSelect}
          onDelete={handleDeselect}
          setNumberOfElements={helpers.handleSetNumberOfElements}
          containerRef={containerRef}
          enableReferences={enableReferences}
        />
      </ListLines>
    </Drawer>
  );
};

export default ContainerAddStixCoreObjectsInLine;
