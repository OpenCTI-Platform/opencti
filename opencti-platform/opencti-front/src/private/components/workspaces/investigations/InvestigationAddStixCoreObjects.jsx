import React, { useState } from 'react';
import * as R from 'ramda';
import IconButton from '@mui/material/IconButton';
import { Add } from '@mui/icons-material';
import Tooltip from '@mui/material/Tooltip';
import InvestigationAddStixCoreObjectsLines
, {
  investigationAddStixCoreObjectsLinesQuery,
} from './InvestigationAddStixCoreObjectsLines';
import { QueryRenderer } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import { stixCyberObservableTypes, stixDomainObjectTypes } from '../../../../utils/hooks/useAttributes';
import { UserContext } from '../../../../utils/hooks/useAuth';
import ListLines from '../../../../components/list_lines/ListLines';
import { isUniqFilter } from '../../../../utils/filters/filtersUtils';
import { convertFilters } from '../../../../utils/ListParameters';
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
  const { t } = useFormatter();
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

  const finalFilters = convertFilters(filters);
  const searchPaginationOptions = {
    types: [resolveAvailableTypes()],
    search: mapping && searchTerm.length === 0 ? selectedText : searchTerm,
    filters: finalFilters,
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
      {!mapping && (
        <Tooltip title={t('Add an entity to this investigation')}>
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
        title={t('Add entities')}
      >
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
                  query={investigationAddStixCoreObjectsLinesQuery}
                  variables={{ count: 100, ...searchPaginationOptions }}
                  render={({ props: renderProps }) => (
                    <InvestigationAddStixCoreObjectsLines
                      data={renderProps}
                      workspaceId={workspaceId}
                      dataColumns={buildColumns(platformModuleHelpers)}
                      initialLoading={renderProps === null}
                      onAdd={onAdd}
                      onDelete={onDelete}
                      mapping={mapping}
                      setNumberOfElements={setNumberOfElements}
                      workspaceStixCoreObjects={workspaceStixCoreObjects}
                    />
                  )}
                />
              </ListLines>
            </div>
          )}
        </UserContext.Consumer>
      </Drawer>
    </div>
  );
};

export default InvestigationAddStixCoreObjects;
