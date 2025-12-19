import React, { useRef, useState } from 'react';
import IconButton from '@common/button/IconButton';
import { Add } from '@mui/icons-material';
import Tooltip from '@mui/material/Tooltip';
import InvestigationAddStixCoreObjectsLines, { investigationAddStixCoreObjectsLinesQuery } from './InvestigationAddStixCoreObjectsLines';
import { QueryRenderer } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import useAttributes from '../../../../utils/hooks/useAttributes';
import useAuth from '../../../../utils/hooks/useAuth';
import ListLines from '../../../../components/list_lines/ListLines';
import { emptyFilterGroup } from '../../../../utils/filters/filtersUtils';
import Drawer from '../../common/drawer/Drawer';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';

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

  const isTypeDomainObject = (types) => {
    return !types
      || types.some((r) => stixDomainObjectTypes.indexOf(r) >= 0)
      || (types.length === 1 && types[0] === 'Stix-Domain-Object');
  };
  const isTypeObservable = (types) => {
    return !types
      || types.some((r) => stixCyberObservableTypes.indexOf(r) >= 0)
      || (types.length === 1 && types[0] === 'Stix-Cyber-Observable');
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

  const LOCAL_STORAGE_KEY = `investigation-${workspaceId}-add-objects`;
  const { viewStorage, helpers, paginationOptions: addObjectsPaginationOptions } = usePaginationLocalStorage(
    LOCAL_STORAGE_KEY,
    {
      searchTerm: '',
      sortBy: '_score',
      orderAsc: false,
      filters: targetStixCoreObjectTypes
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
      types: [resolveAvailableTypes()],
      numberOfElements: {
        number: 0,
        symbol: '',
      },
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

  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();
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

  const keyword = mapping && (searchTerm ?? '').length === 0 ? selectedText : searchTerm;
  const searchPaginationOptions = {
    ...addObjectsPaginationOptions,
    search: keyword,
  };

  return (
    <>
      {!mapping && (
        <Tooltip title={t_i18n('Add an entity to this investigation')}>
          <IconButton
            color="primary"
            aria-label="Add"
            onClick={() => setOpen(true)}
          >
            <Add />
          </IconButton>
        </Tooltip>
      )}
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
            query={investigationAddStixCoreObjectsLinesQuery}
            variables={{ count: 100, ...searchPaginationOptions }}
            render={({ props: renderProps }) => (
              <InvestigationAddStixCoreObjectsLines
                data={renderProps}
                workspaceId={workspaceId}
                paginationOptions={searchPaginationOptions}
                dataColumns={buildColumns()}
                initialLoading={renderProps === null}
                workspaceStixCoreObjects={workspaceStixCoreObjects}
                onAdd={onAdd}
                onDelete={onDelete}
                setNumberOfElements={helpers.handleSetNumberOfElements}
                mapping={mapping}
                containerRef={containerRef}
              />
            )}
          />
        </ListLines>
      </Drawer>
    </>
  );
};

export default InvestigationAddStixCoreObjects;
