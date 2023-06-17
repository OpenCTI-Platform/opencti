/*
Copyright (c) 2021-2023 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Non-Commercial License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import React from 'react';
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

const LOCAL_STORAGE_KEY = 'view-audit';

const useStyles = makeStyles<Theme>(() => ({
  container: {
    margin: 0,
      padding: '0 200px 50px 0',
  },
}));

const Audit = () => {
  const classes = useStyles();
  const { viewStorage, paginationOptions, helpers: storageHelpers } = usePaginationLocalStorage<AuditLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      numberOfElements: { number: 0, symbol: '', original: 0 },
      filters: {},
      searchTerm: '',
      sortBy: 'timestamp',
      orderAsc: false,
      openExports: false,
      types: ['Activity'],
      count: 25,
    },
  );

  const { numberOfElements, filters, searchTerm, sortBy, orderAsc, types } = viewStorage;
  const { selectedElements, deSelectedElements, selectAll, onToggleEntity } = useEntityToggle<AuditLine_node$data>('view-audit');
  const dataColumns = {
    timestamp: {
      label: 'timestamp',
      width: '25%',
      isSortable: true,
    },
    message: {
      label: 'Message',
      width: '75%',
      isSortable: false,
    },
  };
  const queryRef = useQueryLoading<AuditLinesPaginationQuery>(AuditLinesQuery, paginationOptions);

  const extraFields = <div style={{ float: 'left' }}>
      <FormControlLabel value="start"
        control={<Checkbox style={{ padding: 7 }} onChange={() => {
          const newTypes = types?.length === 1 ? ['History', 'Activity'] : ['Activity'];
          storageHelpers.handleAddProperty('types', newTypes);
        }} checked={types?.length === 2}/>}
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
              'members_user',
              'members_organization',
              'members_group',
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
