import React from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import SubTypesLines, { subTypesLinesQuery } from './SubTypesLines';
import ListLines from '../../../../components/list_lines/ListLines';
import { SubTypeLineDummy } from './SubTypesLine';
import { SubTypesLinesQuery, SubTypesLinesQuery$variables } from './__generated__/SubTypesLinesQuery.graphql';
import useEntityToggle from '../../../../utils/hooks/useEntityToggle';
import ToolBar from './ToolBar';
import CustomizationMenu from '../CustomizationMenu';
import Breadcrumbs from '../../../../components/Breadcrumps';
import { useFormatter } from '../../../../components/i18n';

const LOCAL_STORAGE_KEY_SUB_TYPES = 'sub-types';

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
    padding: '0 200px 50px 0',
  },
}));

const SubTypes = () => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<SubTypesLinesQuery$variables>(
    LOCAL_STORAGE_KEY_SUB_TYPES,
    { searchTerm: '' },
  );
  const dataColumns = {
    entity_type: {
      label: 'Entity type',
      width: '30%',
      isSortable: false,
    },
    workflow_status: {
      label: 'Workflow status',
      width: '15%',
      isSortable: false,
    },
    enforce_reference: {
      label: 'Enforce references',
      width: '15%',
      isSortable: false,
    },
    automatic_references: {
      label: 'Automatic references at file upload',
      width: '15%',
      isSortable: false,
    },
    hidden: {
      label: 'Hidden in interface',
      width: '15%',
      isSortable: false,
    },
  };
  const { searchTerm } = viewStorage;
  const queryRef = useQueryLoading<SubTypesLinesQuery>(
    subTypesLinesQuery,
    paginationOptions,
  );
  const {
    onToggleEntity,
    numberOfSelectedElements,
    handleClearSelectedElements,
    selectedElements,
    deSelectedElements,
    handleToggleSelectAll,
    selectAll,
  } = useEntityToggle(LOCAL_STORAGE_KEY_SUB_TYPES);
  return (
    <div className={classes.container}>
      <CustomizationMenu />
      <Breadcrumbs variant="list" elements={[{ label: t_i18n('Settings') }, { label: t_i18n('Customization') }, { label: t_i18n('Entity types'), current: true }]} />
      <ListLines
        handleSearch={helpers.handleSearch}
        keyword={searchTerm}
        dataColumns={dataColumns}
        iconExtension={true}
        selectAll={selectAll}
        handleToggleSelectAll={handleToggleSelectAll}
      >
        {queryRef && (
          <React.Suspense
            fallback={
              <>
                {Array.from(Array(20).keys()).map((idx) => (
                  <SubTypeLineDummy key={idx} dataColumns={dataColumns} />
                ))}
              </>
            }
          >
            <SubTypesLines
              queryRef={queryRef}
              keyword={searchTerm}
              dataColumns={dataColumns}
              setNumberOfElements={helpers.handleSetNumberOfElements}
              selectedElements={selectedElements}
              deSelectedElements={deSelectedElements}
              selectAll={selectAll}
              onToggleEntity={onToggleEntity}
            />
            <ToolBar
              keyword={searchTerm}
              numberOfSelectedElements={numberOfSelectedElements}
              selectedElements={selectedElements}
              selectAll={selectAll}
              handleClearSelectedElements={handleClearSelectedElements}
            />
          </React.Suspense>
        )}
      </ListLines>
    </div>
  );
};

export default SubTypes;
