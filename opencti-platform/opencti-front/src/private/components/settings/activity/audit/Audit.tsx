import React, { useState } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import Checkbox from '@mui/material/Checkbox';
import FormControlLabel from '@mui/material/FormControlLabel';
import ActivityMenu from '../../ActivityMenu';
import { Theme } from '../../../../../components/Theme';
import ListLines from '../../../../../components/list_lines/ListLines';
import { usePaginationLocalStorage } from '../../../../../utils/hooks/useLocalStorage';
import useEntityToggle from '../../../../../utils/hooks/useEntityToggle';
import {
  AuditLinesPaginationQuery,
  AuditLinesPaginationQuery$variables,
} from './__generated__/AuditLinesPaginationQuery.graphql';
import useQueryLoading from '../../../../../utils/hooks/useQueryLoading';
import AuditLines, { AuditLinesQuery } from './AuditLines';
import { AuditLine_node$data } from './__generated__/AuditLine_node.graphql';
import { AuditLineDummy } from './AuditLine';

// ------------------------------------------------------------------------ //
//     OpenCTI Enterprise Edition License                                   //
// ------------------------------------------------------------------------ //
//     Copyright (c) 2021-2023 Filigran SAS                                 //
//                                                                          //
// This file is part of the OpenCTI Enterprise Edition ("EE") and is        //
// licensed under the OpenCTI Non-Commercial License (the "License");       //
// you may not use this file except in compliance with the License.         //
// You may obtain a copy of the License at                                  //
//                                                                          //
// https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE          //
//                                                                          //
// Unless required by applicable law or agreed to in writing, software      //
// distributed under the License is distributed on an "AS IS" BASIS,        //
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. //
// ------------------------------------------------------------------------ //

const LOCAL_STORAGE_KEY = 'view-audit';

const useStyles = makeStyles<Theme>((theme) => ({
  container: {
    margin: 0,
    padding: '0 200px 0 0',
  },
  gridContainer: {
    marginBottom: 20,
  },
  title: {
    float: 'left',
    textTransform: 'uppercase',
  },
  popover: {
    float: 'left',
    marginTop: '-13px',
  },
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
  editButton: {
    position: 'fixed',
    bottom: 30,
    right: 230,
  },
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    overflow: 'auto',
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
}));

const Audit = () => {
  const classes = useStyles();
  const [withHistory, setWithHistory] = useState(false);

  const {
    viewStorage,
    paginationOptions,
    helpers: storageHelpers,
  } = usePaginationLocalStorage<AuditLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      numberOfElements: { number: 0, symbol: '', original: 0 },
      filters: {},
      searchTerm: '',
      sortBy: 'timestamp',
      orderAsc: false,
      openExports: false,
      count: 25,
    },
  );
  storageHelpers.handleAddProperty('types', withHistory ? ['History', 'Audit'] : ['Audit']);

  const {
    numberOfElements,
    filters,
    searchTerm,
    sortBy,
    orderAsc,
  } = viewStorage;

  const {
    selectedElements,
    deSelectedElements,
    selectAll,
    onToggleEntity,
  } = useEntityToggle<AuditLine_node$data>('view-audit');

  const dataColumns = {
    timestamp: {
      label: 'timestamp',
      width: '25%',
      isSortable: true,
    },
    creator: {
      label: 'User',
      width: '15%',
      isSortable: false,
    },
    message: {
      label: 'Message',
      width: '60%',
      isSortable: false,
    },
  };
  const queryRef = useQueryLoading<AuditLinesPaginationQuery>(
    AuditLinesQuery,
    paginationOptions,
  );

  const extraFields = <div style={{ float: 'left' }}>
      <FormControlLabel
        value="start"
        control={<Checkbox style={{ padding: 7 }} onChange={() => setWithHistory(!withHistory)} checked={withHistory}/>}
        label="Include knowledge"
        labelPlacement="end"
    />
  </div>;

  return (
      <div className={classes.container}>
        <ActivityMenu />
        <ListLines sortBy={sortBy}
            orderAsc={orderAsc}
            dataColumns={dataColumns}
            handleSort={storageHelpers.handleSort}
            handleSearch={storageHelpers.handleSearch}
            handleAddFilter={storageHelpers.handleAddFilter}
            handleRemoveFilter={storageHelpers.handleRemoveFilter}
            selectAll={selectAll}
            extraFields={extraFields}
            keyword={searchTerm}
            filters={filters}
            paginationOptions={paginationOptions}
            numberOfElements={numberOfElements}
            availableFilterKeys={[
              'elementId',
              'creator',
              'organization',
              'group',
              'created_start_date',
              'created_end_date',
            ]}>
          {queryRef && (
              <React.Suspense fallback={<>{Array(20).fill(0).map((idx) => (<AuditLineDummy key={idx} dataColumns={dataColumns}/>))}</>}>
                <AuditLines
                    queryRef={queryRef}
                    paginationOptions={paginationOptions}
                    dataColumns={dataColumns}
                    onLabelClick={storageHelpers.handleAddFilter}
                    selectedElements={selectedElements}
                    deSelectedElements={deSelectedElements}
                    onToggleEntity={onToggleEntity}
                    selectAll={selectAll}
                    setNumberOfElements={storageHelpers.handleSetNumberOfElements}
                />
              </React.Suspense>
          )}
        </ListLines>
      </div>
  );
};

export default Audit;
