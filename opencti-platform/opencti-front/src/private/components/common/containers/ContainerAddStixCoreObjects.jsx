import React, { useRef, useState } from 'react';
import IconButton from '@common/button/IconButton';
import Fab from '@mui/material/Fab';
import { Add } from '@mui/icons-material';
import Tooltip from '@mui/material/Tooltip';
import SpeedDial from '@mui/material/SpeedDial';
import SpeedDialIcon from '@mui/material/SpeedDialIcon';
import SpeedDialAction from '@mui/material/SpeedDialAction';
import { GlobeModel, HexagonOutline } from 'mdi-material-ui';
import makeStyles from '@mui/styles/makeStyles';
import { QueryRenderer } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import ContainerAddStixCoreObjectsLines, { containerAddStixCoreObjectsLinesQuery } from './ContainerAddStixCoreObjectsLines';
import StixDomainObjectCreation from '../stix_domain_objects/StixDomainObjectCreation';
import StixCyberObservableCreation from '../../observations/stix_cyber_observables/StixCyberObservableCreation';
import useAuth from '../../../../utils/hooks/useAuth';
import ListLines from '../../../../components/list_lines/ListLines';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../../utils/filters/filtersUtils';
import Drawer from '../drawer/Drawer';
import useAttributes from '../../../../utils/hooks/useAttributes';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import { removeEmptyFields } from '../../../../utils/utils';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles((theme) => ({
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
  speedDial: {
    position: 'fixed',
    bottom: 30,
    right: 30,
    zIndex: 2000,
  },
  speedDialButton: {
    backgroundColor: theme.palette.primary.main,
    color: theme.palette.primary.contrastText,
    '&:hover': {
      backgroundColor: theme.palette.primary.main,
    },
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
  } = props;
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const [open, setOpen] = useState(false);
  const [openSpeedDial, setOpenSpeedDial] = useState(false);
  const [openCreateEntity, setOpenCreateEntity] = useState(false);
  const [openCreateObservable, setOpenCreateObservable] = useState(false);

  const { stixDomainObjectTypes, stixCyberObservableTypes } = useAttributes();
  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();

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
      filters: emptyFilterGroup,
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
  const contextFilters = useBuildEntityTypeBasedFilterContext(targetStixCoreObjectTypes, filters);

  const containerRef = useRef(null);
  const [mappingSearch, setMappingSearch] = useState(null);
  const [currentSelectedText, setCurrentSelectedText] = useState(selectedText);
  if (currentSelectedText !== selectedText) {
    setMappingSearch(null);
    setCurrentSelectedText(selectedText);
  }
  let keyword;
  if (!mapping) {
    keyword = searchTerm;
  } else {
    keyword = !mappingSearch ? selectedText : mappingSearch;
  }
  const handleOpenCreateEntity = () => {
    setOpenCreateEntity(true);
    setOpenSpeedDial(false);
  };
  const handleCloseCreateEntity = () => {
    setOpenCreateEntity(false);
    setOpenSpeedDial(false);
  };
  const handleOpenCreateObservable = () => {
    setOpenCreateObservable(true);
    setOpenSpeedDial(false);
  };
  const handleCloseCreateObservable = () => {
    setOpenCreateObservable(false);
    setOpenSpeedDial(false);
  };
  const renderDomainObjectCreation = (searchPaginationOptions) => {
    return (
      <StixDomainObjectCreation
        display={open}
        inputValue={keyword}
        paginationKey="Pagination_stixCoreObjects"
        paginationOptions={searchPaginationOptions}
        confidence={confidence}
        defaultCreatedBy={defaultCreatedBy}
        defaultMarkingDefinitions={defaultMarkingDefinitions}
        stixDomainObjectTypes={
          targetStixCoreObjectTypes && targetStixCoreObjectTypes.length > 0
            ? targetStixCoreObjectTypes
            : []
        }
      />
    );
  };
  const renderObservableCreation = (searchPaginationOptions) => {
    return (
      <StixCyberObservableCreation
        display={open}
        contextual={true}
        inputValue={keyword}
        paginationKey="Pagination_stixCoreObjects"
        paginationOptions={searchPaginationOptions}
        defaultCreatedBy={defaultCreatedBy}
        defaultMarkingDefinitions={defaultMarkingDefinitions}
      />
    );
  };
  const renderStixCoreObjectCreation = (searchPaginationOptions) => {
    return (
      <>
        <SpeedDial
          className={classes.createButton}
          ariaLabel="Create"
          icon={<SpeedDialIcon />}
          onClose={() => setOpenSpeedDial(false)}
          onOpen={() => setOpenSpeedDial(true)}
          open={openSpeedDial}
          FabProps={{
            color: 'secondary',
          }}
        >
          <SpeedDialAction
            title={t_i18n('Create an observable')}
            icon={<HexagonOutline />}
            tooltipTitle={t_i18n('Create an observable')}
            onClick={() => handleOpenCreateObservable()}
            FabProps={{
              classes: { root: classes.speedDialButton },
            }}
          />
          <SpeedDialAction
            title={t_i18n('Create an entity')}
            icon={<GlobeModel />}
            tooltipTitle={t_i18n('Create an entity')}
            onClick={() => handleOpenCreateEntity()}
            FabProps={{
              classes: { root: classes.speedDialButton },
            }}
          />
        </SpeedDial>
        <StixDomainObjectCreation
          display={open}
          inputValue={keyword}
          paginationKey="Pagination_stixCoreObjects"
          paginationOptions={searchPaginationOptions}
          confidence={confidence}
          defaultCreatedBy={defaultCreatedBy}
          defaultMarkingDefinitions={defaultMarkingDefinitions}
          stixCoreObjectTypes={
            targetStixCoreObjectTypes && targetStixCoreObjectTypes.length > 0
              ? targetStixCoreObjectTypes
              : []
          }
          speeddial={true}
          open={openCreateEntity}
          handleClose={() => handleCloseCreateEntity()}
        />
        <StixCyberObservableCreation
          display={open}
          contextual={true}
          inputValue={keyword}
          paginationKey="Pagination_stixCoreObjects"
          paginationOptions={searchPaginationOptions}
          defaultCreatedBy={defaultCreatedBy}
          defaultMarkingDefinitions={defaultMarkingDefinitions}
          speeddial={true}
          open={openCreateObservable}
          handleClose={() => handleCloseCreateObservable()}
        />
      </>
    );
  };
  const renderEntityCreation = (searchPaginationOptions) => {
    if (
      targetStixCoreObjectTypes
      && isTypeDomainObject(targetStixCoreObjectTypes)
      && !isTypeObservable(targetStixCoreObjectTypes)
    ) {
      return renderDomainObjectCreation(searchPaginationOptions);
    }
    if (
      targetStixCoreObjectTypes
      && isTypeObservable(targetStixCoreObjectTypes)
      && !isTypeDomainObject(targetStixCoreObjectTypes)
    ) {
      return renderObservableCreation(searchPaginationOptions);
    }
    if (
      !targetStixCoreObjectTypes
      || (isTypeObservable(targetStixCoreObjectTypes)
        && isTypeDomainObject(targetStixCoreObjectTypes))
    ) {
      return renderStixCoreObjectCreation(searchPaginationOptions);
    }
    return null;
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
        handleSearch={mapping ? setMappingSearch : helpers.handleSearch}
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
        additionalFilterKeys={{
          filterKeys: ['entity_type'],
        }}
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
              onLabelClick={helpers.handleAddFilter}
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
    filters: contextFilters,
  });
  const renderButton = () => {
    if (knowledgeGraph) {
      return (
        <Tooltip title={t_i18n('Add an entity to this container')}>
          <IconButton
            aria-label="Add"
            onClick={() => setOpen(true)}
            variant="tertiary"
            size="small"
          >
            <Add />
          </IconButton>
        </Tooltip>
      );
    }
    if (simple) {
      return (
        <IconButton
          aria-label="Add"
          onClick={() => setOpen(true)}
          variant="tertiary"
          size="small"
        >
          <Add />
        </IconButton>
      );
    }
    return (
      <Fab
        onClick={() => setOpen(true)}
        color="primary"
        aria-label="Add"
        className={withPadding ? classes.createButtonWithPadding : classes.createButton}
      >
        <Add />
      </Fab>
    );
  };
  return (
    <>
      {!mapping && renderButton()}
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
      >
        <>
          {renderSearchResults(searchPaginationOptions)}
          {renderEntityCreation(searchPaginationOptions)}
        </>
      </Drawer>
    </>
  );
};

export default ContainerAddStixCoreObjects;
