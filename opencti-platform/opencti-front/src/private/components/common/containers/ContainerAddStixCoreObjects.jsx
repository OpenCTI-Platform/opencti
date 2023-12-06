import React, { useRef, useState } from 'react';
import IconButton from '@mui/material/IconButton';
import Fab from '@mui/material/Fab';
import { Add } from '@mui/icons-material';
import Tooltip from '@mui/material/Tooltip';
import makeStyles from '@mui/styles/makeStyles';
import { Button } from '@mui/material';
import { QueryRenderer } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import ContainerAddStixCoreObjectsLines, { containerAddStixCoreObjectsLinesQuery } from './ContainerAddStixCoreObjectsLines';
import StixDomainObjectCreation from '../stix_domain_objects/StixDomainObjectCreation';
import StixCyberObservableCreation from '../../observations/stix_cyber_observables/StixCyberObservableCreation';
import useAuth from '../../../../utils/hooks/useAuth';
import ListLines from '../../../../components/list_lines/ListLines';
import { emptyFilterGroup } from '../../../../utils/filters/filtersUtils';
import Drawer from '../drawer/Drawer';
import useAttributes from '../../../../utils/hooks/useAttributes';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import { removeEmptyFields } from '../../../../utils/utils';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
    zIndex: 1100,
  },
  createButtonWithPadding: {
    position: 'fixed',
    bottom: 30,
    right: 280,
    zIndex: 1100,
  },
  createButtonSimple: {
    float: 'left',
    marginTop: -15,
  },
}));

const ContainerAddStixCoreObjects = (props) => {
  const {
    targetStixCoreObjectTypes,
    defaultCreatedBy,
    defaultMarkingDefinitions,
    containerId,
    knowledgeGraph,
    containerStixCoreObjects,
    confidence,
    withPadding,
    simple,
    paginationOptions,
    onAdd,
    onDelete,
    mapping,
    selectedText,
    openDrawer,
    handleClose,
    enableReferences,
    controlledDial,
  } = props;
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const [open, setOpen] = useState(false);

  const { stixDomainObjectTypes, stixCyberObservableTypes } = useAttributes();
  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();

  const targetEntityTypesFilterGroup = {
    mode: 'and',
    filterGroups: [],
    filters: [
      {
        key: 'entity_type',
        values: targetStixCoreObjectTypes,
        operator: 'eq',
        mode: 'or',
      },
    ],
  };

  const isTypeDomainObject = (types) => {
    return !types
      || types.some((r) => stixDomainObjectTypes.indexOf(r) >= 0)
      || types.includes('Stix-Domain-Object');
  };
  const isTypeObservable = (types) => {
    return !types
      || types.some((r) => stixCyberObservableTypes.indexOf(r) >= 0)
      || types.includes('Stix-Cyber-Observable');
  };

  const resolveAvailableTypes = () => {
    if (
      targetStixCoreObjectTypes
      && isTypeDomainObject(targetStixCoreObjectTypes)
      && !isTypeObservable(targetStixCoreObjectTypes)
    ) {
      return 'Stix-Domain-Object';
    }
    if (
      targetStixCoreObjectTypes
      && isTypeObservable(targetStixCoreObjectTypes)
      && !isTypeDomainObject(targetStixCoreObjectTypes)
    ) {
      return 'Stix-Cyber-Observable';
    }
    if (
      !targetStixCoreObjectTypes
      || (isTypeObservable(targetStixCoreObjectTypes)
        && isTypeDomainObject(targetStixCoreObjectTypes))
    ) {
      return 'Stix-Core-Object';
    }
    return null;
  };

  const LOCAL_STORAGE_KEY = `container-${containerId}-add-${targetStixCoreObjectTypes}`;
  const { viewStorage, helpers, paginationOptions: addObjectsPaginationOptions } = usePaginationLocalStorage(
    LOCAL_STORAGE_KEY,
    {
      searchTerm: '',
      sortBy: '_score',
      orderAsc: false,
      filters: targetStixCoreObjectTypes
      && !(targetStixCoreObjectTypes.includes('Stix-Domain-Object') || targetStixCoreObjectTypes.includes('Stix-Cyber-Observable'))
        ? targetEntityTypesFilterGroup
        : emptyFilterGroup,
      types: [resolveAvailableTypes()],
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
  const keyword = mapping && (searchTerm ?? '').length === 0 ? selectedText : searchTerm;
  const renderDomainObjectCreation = (searchPaginationOptions) => {
    return (
      <StixDomainObjectCreation
        display={true}
        inputValue={keyword}
        paginationKey="Pagination_stixCoreObjects"
        paginationOptions={searchPaginationOptions}
        controlledDial={({ onOpen }) => (
          <Button
            variant='outlined'
            onClick={onOpen}
            disableElevation
            data-testid="create_entity"
          >
            {t_i18n('Create Entity')} <Add />
          </Button>
        )}
        confidence={confidence}
        defaultCreatedBy={defaultCreatedBy}
        defaultMarkingDefinitions={defaultMarkingDefinitions}
        stixDomainObjectTypes={
            targetStixCoreObjectTypes && targetStixCoreObjectTypes.length > 0
              ? targetStixCoreObjectTypes
              : []
        }
        creationCallback={undefined}
        open={undefined}
        speeddial={undefined}
        handleClose={undefined}
      />
    );
  };
  const renderObservableCreation = (searchPaginationOptions) => {
    return (
      <StixCyberObservableCreation
        display={true}
        contextual={true}
        inputValue={keyword}
        paginationKey="Pagination_stixCoreObjects"
        paginationOptions={searchPaginationOptions}
        controlledDial={({ onOpen }) => (
          <Button
            variant='outlined'
            style={{ marginLeft: '5px' }}
            onClick={onOpen}
            disableElevation
            data-testid="create_observable"
          >
            {t_i18n('Create Observable')} <Add />
          </Button>
        )}
        confidence={confidence}
        defaultCreatedBy={defaultCreatedBy}
        defaultMarkingDefinitions={defaultMarkingDefinitions}
        stixCoreObjectTypes={
            targetStixCoreObjectTypes && targetStixCoreObjectTypes.length > 0
              ? targetStixCoreObjectTypes
              : []
        }
        open={undefined}
        handleClose={undefined}
      />
    );
  };
  const renderEntityCreation = (searchPaginationOptions) => {
    const isOnlySDOs = targetStixCoreObjectTypes
      && isTypeDomainObject(targetStixCoreObjectTypes)
      && !isTypeObservable(targetStixCoreObjectTypes);
    const isOnlySCOs = targetStixCoreObjectTypes
      && isTypeObservable(targetStixCoreObjectTypes)
      && !isTypeDomainObject(targetStixCoreObjectTypes);
    const renderBoth = !targetStixCoreObjectTypes
      || (isTypeObservable(targetStixCoreObjectTypes)
        && isTypeDomainObject(targetStixCoreObjectTypes));
    return (
      <div style={{ float: 'right', marginTop: '-60px', display: 'flex' }}>
        {(isOnlySDOs || renderBoth) && renderDomainObjectCreation(searchPaginationOptions)}
        {(isOnlySCOs || renderBoth) && renderObservableCreation(searchPaginationOptions)}
      </div>
    );
  };
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
  const renderSearchResults = (searchPaginationOptions) => {
    return (
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
        <QueryRenderer
          query={containerAddStixCoreObjectsLinesQuery}
          variables={{ count: 100, ...searchPaginationOptions }}
          render={({ props: renderProps }) => (
            <ContainerAddStixCoreObjectsLines
              data={renderProps}
              containerId={containerId}
              paginationOptions={paginationOptions}
              dataColumns={buildColumns()}
              initialLoading={renderProps === null}
              knowledgeGraph={knowledgeGraph}
              containerStixCoreObjects={containerStixCoreObjects}
              onAdd={onAdd}
              onDelete={onDelete}
              setNumberOfElements={helpers.handleSetNumberOfElements}
              mapping={mapping}
              containerRef={containerRef}
              enableReferences={enableReferences}
            />
          )}
        />
      </ListLines>
    );
  };

  const { count: _, ...paginationOptionsNoCount } = addObjectsPaginationOptions;
  const searchPaginationOptions = removeEmptyFields({
    ...paginationOptionsNoCount,
    search: keyword,
  });
  const renderButton = () => {
    if (knowledgeGraph) {
      return (
        <Tooltip title={t_i18n('Add an entity to this container')}>
          <IconButton
            color="primary"
            aria-label="Add"
            onClick={() => setOpen(true)}
            size="large"
          >
            <Add/>
          </IconButton>
        </Tooltip>
      );
    }
    if (simple) {
      return (
        <IconButton
          color="primary"
          aria-label="Add"
          onClick={() => setOpen(true)}
          classes={{ root: classes.createButtonSimple }}
          size="large"
        >
          <Add fontSize="small"/>
        </IconButton>
      );
    }
    return (
      <Fab
        onClick={() => setOpen(true)}
        color="secondary"
        aria-label="Add"
        className={withPadding ? classes.createButtonWithPadding : classes.createButton}
      >
        <Add/>
      </Fab>
    );
  };
  return (
    <>
      {!mapping && controlledDial === undefined && renderButton()}
      <Drawer
        open={mapping ? openDrawer : open}
        onClose={() => {
          if (mapping) {
            handleClose();
          } else {
            setOpen(false);
          }
        }}
        title={t_i18n('Add entities')}
        containerRef={containerRef}
        controlledDial={controlledDial}
      >
        <>
          {renderEntityCreation(searchPaginationOptions)}
          {renderSearchResults(searchPaginationOptions)}
        </>
      </Drawer>
    </>
  );
};

export default ContainerAddStixCoreObjects;
