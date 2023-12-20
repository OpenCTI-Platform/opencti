import React, { useRef, useState } from 'react';
import IconButton from '@mui/material/IconButton';
import { Add } from '@mui/icons-material';
import Tooltip from '@mui/material/Tooltip';
import InvestigationAddStixCoreObjectsLines, { investigationAddStixCoreObjectsLinesQuery } from './InvestigationAddStixCoreObjectsLines';
import { QueryRenderer } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import useAttributes from '../../../../utils/hooks/useAttributes';
import { UserContext } from '../../../../utils/hooks/useAuth';
import ListLines from '../../../../components/list_lines/ListLines';
import { constructHandleAddFilter, constructHandleRemoveFilter, emptyFilterGroup, filtersAfterSwitchLocalMode } from '../../../../utils/filters/filtersUtils';
import Drawer from '../../common/drawer/Drawer';

const InvestigationAddStixCoreObjects = (props) => {
  const {
    targetStixCoreObjectTypes,
    workspaceId,
    onAdd,
    onDelete,
    selectedText,
    openDrawer,
    handleClose,
    mapping,
    workspaceStixCoreObjects,
  } = props;
  const { t_i18n } = useFormatter();
  const { stixDomainObjectTypes, stixCyberObservableTypes } = useAttributes();
  const [open, setOpen] = useState(false);
  const [sortBy, setSortBy] = useState('_score');
  const [orderAsc, setOrderAsc] = useState(false);
  const [filters, setFilters] = useState(
    targetStixCoreObjectTypes
    && !(
      targetStixCoreObjectTypes.includes('Stix-Domain-Object')
      || targetStixCoreObjectTypes.includes('Stix-Cyber-Observable')
    )
      ? {
        mode: 'and',
        filters: [{
          key: 'entity_type',
          values: targetStixCoreObjectTypes,
        }],
        filterGroups: [],
      }
      : emptyFilterGroup,
  );
  const [numberOfElements, setNumberOfElements] = useState({
    number: 0,
    symbol: '',
  });
  const [searchTerm, setSearchTerm] = useState('');
  const containerRef = useRef(null);
  const handleSort = (field, sortOrderAsc) => {
    setSortBy(field);
    setOrderAsc(sortOrderAsc);
  };
  const handleAddFilter = (key, id, op = 'eq', event = null) => {
    if (event) {
      event.stopPropagation();
      event.preventDefault();
    }
    setFilters(constructHandleAddFilter(filters, key, id, op));
  };
  const handleRemoveFilter = (key, op = 'eq') => {
    setFilters(constructHandleRemoveFilter(filters, key, op));
  };
  const handleSwitchLocalMode = (localFilter) => {
    setFilters(filtersAfterSwitchLocalMode(filters, localFilter));
  };

  const handleSwitchGlobalMode = () => {
    if (filters) {
      setFilters({
        ...filters,
        mode: filters.mode === 'and' ? 'or' : 'and',
      });
    }
  };
  const isTypeDomainObject = (types) => {
    return !types || types.some((r) => stixDomainObjectTypes.indexOf(r) >= 0);
  };
  const isTypeObservable = (types) => {
    return (
      !types || types.some((r) => stixCyberObservableTypes.indexOf(r) >= 0)
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

  const searchPaginationOptions = {
    types: [resolveAvailableTypes()],
    search: mapping && searchTerm.length === 0 ? selectedText : searchTerm,
    filters,
    orderBy: sortBy,
    orderMode: orderAsc ? 'asc' : 'desc',
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
          mode: 'and',
          filters: [{
            key: 'entity_type',
            values: targetStixCoreObjectTypes,
          }],
          filterGroups: [],
        }
        : emptyFilterGroup,
    );
  };

  return (
    <>
      {!mapping && (
        <Tooltip title={t_i18n('Add an entity to this investigation')}>
          <IconButton
            color="primary"
            aria-label="Add"
            onClick={() => setOpen(true)}
            size="large"
          >
            <Add />
          </IconButton>
        </Tooltip>
      )}
      <Drawer
        open={mapping ? openDrawer : open}
        onClose={() => {
          resetState();
          if (mapping) {
            handleClose();
          } else {
            setOpen(false);
          }
        }}
        title={t_i18n('Add entities')}
        containerRef={containerRef}
      >
        <UserContext.Consumer>
          {({ platformModuleHelpers }) => (
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
              handleSwitchLocalMode={handleSwitchLocalMode}
              handleSwitchGlobalMode={handleSwitchGlobalMode}
              disableCards={true}
              filters={filters}
              paginationOptions={searchPaginationOptions}
              numberOfElements={numberOfElements}
              iconExtension={true}
              parametersWithPadding={true}
              disableExport={true}
              availableEntityTypes={[resolveAvailableTypes()]}
            >
              <QueryRenderer
                query={investigationAddStixCoreObjectsLinesQuery}
                variables={{ count: 100, ...searchPaginationOptions }}
                render={({ props: renderProps }) => (
                  <InvestigationAddStixCoreObjectsLines
                    data={renderProps}
                    workspaceId={workspaceId}
                    paginationOptions={searchPaginationOptions}
                    dataColumns={buildColumns(platformModuleHelpers)}
                    initialLoading={renderProps === null}
                    workspaceStixCoreObjects={workspaceStixCoreObjects}
                    onAdd={onAdd}
                    onDelete={onDelete}
                    setNumberOfElements={setNumberOfElements}
                    mapping={mapping}
                    containerRef={containerRef}
                  />
                )}
              />
            </ListLines>
          )}
        </UserContext.Consumer>
      </Drawer>
    </>
  );
};

export default InvestigationAddStixCoreObjects;
