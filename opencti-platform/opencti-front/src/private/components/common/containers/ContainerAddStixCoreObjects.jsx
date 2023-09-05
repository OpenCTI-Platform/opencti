import React, { useState, useRef } from 'react';
import * as R from 'ramda';
import Drawer from '@mui/material/Drawer';
import IconButton from '@mui/material/IconButton';
import Typography from '@mui/material/Typography';
import Fab from '@mui/material/Fab';
import { Add, Close } from '@mui/icons-material';
import Tooltip from '@mui/material/Tooltip';
import SpeedDial from '@mui/material/SpeedDial';
import SpeedDialIcon from '@mui/material/SpeedDialIcon';
import SpeedDialAction from '@mui/material/SpeedDialAction';
import { GlobeModel, HexagonOutline } from 'mdi-material-ui';
import makeStyles from '@mui/styles/makeStyles';
import { QueryRenderer } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import ContainerAddStixCoreObjectsLines, {
  containerAddStixCoreObjectsLinesQuery,
} from './ContainerAddStixCoreObjectsLines';
import StixDomainObjectCreation from '../stix_domain_objects/StixDomainObjectCreation';
import StixCyberObservableCreation from '../../observations/stix_cyber_observables/StixCyberObservableCreation';
import {
  stixCyberObservableTypes,
  stixDomainObjectTypes,
} from '../../../../utils/hooks/useAttributes';
import { UserContext } from '../../../../utils/hooks/useAuth';
import ListLines from '../../../../components/list_lines/ListLines';
import { isUniqFilter } from '../../../../utils/filters/filtersUtils';
import { convertFilters } from '../../../../utils/ListParameters';

const useStyles = makeStyles((theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    padding: 0,
    zIndex: 1,
  },
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
  title: {
    float: 'left',
  },
  search: {
    float: 'right',
  },
  header: {
    backgroundColor: theme.palette.background.nav,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
  },
  container: {
    padding: '15px 0 0 0',
    height: '100%',
    width: '100%',
  },
  placeholder: {
    display: 'inline-block',
    height: '1em',
    backgroundColor: theme.palette.grey[700],
  },
  avatar: {
    width: 24,
    height: 24,
  },
  speedDial: {
    position: 'fixed',
    bottom: 30,
    right: 30,
    zIndex: 2000,
  },
  info: {
    paddingTop: 10,
  },
  speedDialButton: {
    backgroundColor: theme.palette.secondary.main,
    color: '#ffffff',
    '&:hover': {
      backgroundColor: theme.palette.secondary.main,
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
    onAdd,
    onDelete,
    mapping,
    selectedText,
    openDrawer,
    handleClose,
  } = props;
  const classes = useStyles();
  const { t } = useFormatter();
  const [open, setOpen] = useState(false);
  const [openSpeedDial, setOpenSpeedDial] = useState(false);
  const [openCreateEntity, setOpenCreateEntity] = useState(false);
  const [openCreateObservable, setOpenCreateObservable] = useState(false);
  const [sortBy, setSortBy] = useState('_score');
  const [orderAsc, setOrderAsc] = useState(false);
  const [filters, setFilters] = useState(
    targetStixCoreObjectTypes
      && !(
        targetStixCoreObjectTypes.includes('Stix-Domain-Object')
        || targetStixCoreObjectTypes.includes('Stix-Cyber-Observable')
      )
      ? {
        entity_type: targetStixCoreObjectTypes.map((n) => ({
          id: n,
          label: n,
          value: n,
        })),
      }
      : {},
  );
  const [numberOfElements, setNumberOfElements] = useState({
    number: 0,
    symbol: '',
  });
  const [searchTerm, setSearchTerm] = useState('');
  const containerRef = useRef(null);
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
  const handleSort = (field, sortOrderAsc) => {
    setSortBy(field);
    setOrderAsc(sortOrderAsc);
  };
  const handleAddFilter = (key, id, value, event = null) => {
    if (event) {
      event.stopPropagation();
      event.preventDefault();
    }
    if (filters[key] && filters[key].length > 0) {
      setFilters(
        R.assoc(
          key,
          isUniqFilter(key)
            ? [{ id, value }]
            : R.uniqBy(R.prop('id'), [{ id, value }, ...filters[key]]),
          filters,
        ),
      );
    } else {
      setFilters(R.assoc(key, [{ id, value }], filters));
    }
  };
  const handleRemoveFilter = (key) => {
    setFilters(R.dissoc(key, filters));
  };
  const isTypeDomainObject = (types) => {
    return !types || types.some((r) => stixDomainObjectTypes.indexOf(r) >= 0);
  };
  const isTypeObservable = (types) => {
    return (
      !types || types.some((r) => stixCyberObservableTypes.indexOf(r) >= 0)
    );
  };
  const renderDomainObjectCreation = (searchPaginationOptions) => {
    return (
      <StixDomainObjectCreation
        display={open}
        inputValue={
          mapping && searchTerm.length === 0 ? selectedText : searchTerm
        }
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
        inputValue={
          mapping && searchTerm.length === 0 ? selectedText : searchTerm
        }
        paginationKey="Pagination_stixCoreObjects"
        paginationOptions={searchPaginationOptions}
        defaultCreatedBy={defaultCreatedBy}
        defaultMarkingDefinitions={defaultMarkingDefinitions}
      />
    );
  };
  const renderStixCoreObjectCreation = (searchPaginationOptions) => {
    return (
      <div>
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
            title={t('Create an observable')}
            icon={<HexagonOutline />}
            tooltipTitle={t('Create an observable')}
            onClick={() => handleOpenCreateObservable()}
            FabProps={{
              classes: { root: classes.speedDialButton },
            }}
          />
          <SpeedDialAction
            title={t('Create an entity')}
            icon={<GlobeModel />}
            tooltipTitle={t('Create an entity')}
            onClick={() => handleOpenCreateEntity()}
            FabProps={{
              classes: { root: classes.speedDialButton },
            }}
          />
        </SpeedDial>
        <StixDomainObjectCreation
          display={open}
          inputValue={
            mapping && searchTerm.length === 0 ? selectedText : searchTerm
          }
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
          inputValue={
            mapping && searchTerm.length === 0 ? selectedText : searchTerm
          }
          paginationKey="Pagination_stixCoreObjects"
          paginationOptions={searchPaginationOptions}
          defaultCreatedBy={defaultCreatedBy}
          defaultMarkingDefinitions={defaultMarkingDefinitions}
          speeddial={true}
          open={openCreateObservable}
          handleClose={() => handleCloseCreateObservable()}
        />
      </div>
    );
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
  const buildColumns = (platformModuleHelpers) => {
    const isRuntimeSort = platformModuleHelpers.isRuntimeFieldEnable();
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
        isSortable: isRuntimeSort,
      },
      objectLabel: {
        label: 'Labels',
        width: '22%',
        isSortable: false,
      },
      objectMarking: {
        label: 'Marking',
        width: '15%',
        isSortable: isRuntimeSort,
      },
    };
  };
  const renderSearchResults = (searchPaginationOptions) => {
    return (
      <UserContext.Consumer>
        {({ platformModuleHelpers }) => (
          <div>
            <ListLines
              sortBy={sortBy}
              orderAsc={orderAsc}
              dataColumns={buildColumns(platformModuleHelpers)}
              handleSearch={setSearchTerm}
              keyword={
                mapping && searchTerm.length === 0 ? selectedText : searchTerm
              }
              handleSort={handleSort}
              handleAddFilter={handleAddFilter}
              handleRemoveFilter={handleRemoveFilter}
              disableCards={true}
              filters={filters}
              paginationOptions={searchPaginationOptions}
              numberOfElements={numberOfElements}
              iconExtension={true}
              parametersWithPadding={true}
              disableExport={true}
              availableEntityTypes={[resolveAvailableTypes()]}
              availableFilterKeys={[
                'entity_type',
                'markedBy',
                'labelledBy',
                'createdBy',
                'confidence',
                'x_opencti_organization_type',
                'created_start_date',
                'created_end_date',
                'created_at_start_date',
                'created_at_end_date',
                'creator',
              ]}
            >
              <QueryRenderer
                query={containerAddStixCoreObjectsLinesQuery}
                variables={{ count: 100, ...searchPaginationOptions }}
                render={({ props: renderProps }) => (
                  <ContainerAddStixCoreObjectsLines
                    data={renderProps}
                    containerId={containerId}
                    paginationOptions={searchPaginationOptions}
                    dataColumns={buildColumns(platformModuleHelpers)}
                    initialLoading={renderProps === null}
                    knowledgeGraph={knowledgeGraph}
                    containerStixCoreObjects={containerStixCoreObjects}
                    onAdd={onAdd}
                    onDelete={onDelete}
                    setNumberOfElements={setNumberOfElements}
                    mapping={mapping}
                    containerRef={containerRef}
                  />
                )}
              />
            </ListLines>
          </div>
        )}
      </UserContext.Consumer>
    );
  };
  const finalFilters = convertFilters(filters);
  const searchPaginationOptions = {
    types: [resolveAvailableTypes()],
    search: mapping && searchTerm.length === 0 ? selectedText : searchTerm,
    filters: finalFilters,
    orderBy: sortBy,
    orderMode: orderAsc ? 'asc' : 'desc',
  };
  const renderButton = () => {
    if (knowledgeGraph) {
      return (
        <Tooltip title={t('Add an entity to this container')}>
          <IconButton
            color="primary"
            aria-label="Add"
            onClick={() => setOpen(true)}
            size="large"
          >
            <Add />
          </IconButton>
        </Tooltip>
      );
    }
    if (simple) {
      return (
        <IconButton
          color="secondary"
          aria-label="Add"
          onClick={() => setOpen(true)}
          classes={{ root: classes.createButtonSimple }}
          size="large"
        >
          <Add fontSize="small" />
        </IconButton>
      );
    }
    return (
      <Fab
        onClick={() => setOpen(true)}
        color="secondary"
        aria-label="Add"
        className={
          withPadding ? classes.createButtonWithPadding : classes.createButton
        }
      >
        <Add />
      </Fab>
    );
  };
  const resetState = () => {
    setSearchTerm('');
    setFilters(
      targetStixCoreObjectTypes
        && !(
          targetStixCoreObjectTypes.includes('Stix-Domain-Object')
          || targetStixCoreObjectTypes.includes('Stix-Cyber-Observable')
        )
        ? {
          entity_type: targetStixCoreObjectTypes.map((n) => ({
            id: n,
            label: n,
            value: n,
          })),
        }
        : {},
    );
  };
  return (
    <div>
      {!mapping && renderButton()}
      <Drawer
        open={mapping ? openDrawer : open}
        anchor="right"
        elevation={1}
        sx={{ zIndex: 1202 }}
        classes={{ paper: classes.drawerPaper }}
        onClose={() => {
          resetState();
          if (mapping) {
            handleClose();
          } else {
            setOpen(false);
          }
        }}
        PaperProps={{
          ref: containerRef,
        }}
      >
        <div className={classes.header}>
          <IconButton
            aria-label="Close"
            className={classes.closeButton}
            onClick={() => {
              resetState();
              if (mapping) {
                handleClose();
              } else {
                setOpen(false);
              }
            }}
            size="large"
            color="primary"
          >
            <Close fontSize="small" color="primary" />
          </IconButton>
          {(isTypeDomainObject(targetStixCoreObjectTypes)
            || isTypeObservable(targetStixCoreObjectTypes)) && (
            <Typography variant="h6" classes={{ root: classes.title }}>
              {t('Add entities')}
            </Typography>
          )}
        </div>
        <div className={classes.container}>
          {renderSearchResults(searchPaginationOptions)}
        </div>
        {renderEntityCreation(searchPaginationOptions)}
      </Drawer>
    </div>
  );
};

export default ContainerAddStixCoreObjects;
