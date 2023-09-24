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

import React, { FunctionComponent } from 'react';
import ProcessingMenu from '@components/data/ProcessingMenu';
import makeStyles from '@mui/styles/makeStyles';
import EnterpriseEdition from '@components/common/EnterpriseEdition';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import ListLines from '../../../components/list_lines/ListLines';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import PlaybookCreation from './playbooks/PlaybookCreation';
import PlaybooksLines, {
  playbooksLinesQuery,
} from './playbooks/PlaybooksLines';
import {
  PlaybooksLinesPaginationQuery,
  PlaybooksLinesPaginationQuery$variables,
} from './playbooks/__generated__/PlaybooksLinesPaginationQuery.graphql';
import { PlaybookLineDummy } from './playbooks/PlaybookLine';
import { Theme } from '../../../components/Theme';
import useEnterpriseEdition from '../../../utils/hooks/useEnterpriseEdition';

export const LOCAL_STORAGE_KEY_PLAYBOOKS = 'view-playbooks';

const useStyles = makeStyles<Theme>(() => ({
  container: {
    margin: 0,
    padding: '0 200px 50px 0',
  },
}));

const Playbooks: FunctionComponent = () => {
  const classes = useStyles();
  const isEnterpriseEdition = useEnterpriseEdition();
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<PlaybooksLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY_PLAYBOOKS,
    {
      searchTerm: '',
      sortBy: 'name',
      orderAsc: true,
      numberOfElements: {
        number: 0,
        symbol: '',
      },
    },
  );
  const renderLines = () => {
    const { searchTerm, sortBy, orderAsc, numberOfElements } = viewStorage;
    const dataColumns = {
      name: {
        label: 'Name',
        width: '35%',
        isSortable: true,
      },
      description: {
        label: 'Description',
        width: '40%',
        isSortable: false,
      },
      playbook_running: {
        label: 'Running',
        width: '15%',
        isSortable: true,
      },
    };
    const queryRef = useQueryLoading<PlaybooksLinesPaginationQuery>(
      playbooksLinesQuery,
      paginationOptions,
    );
    return (
      <ListLines
        sortBy={sortBy}
        orderAsc={orderAsc}
        dataColumns={dataColumns}
        handleSort={helpers.handleSort}
        handleSearch={helpers.handleSearch}
        keyword={searchTerm}
        paginationOptions={paginationOptions}
        numberOfElements={numberOfElements}
      >
        {queryRef && (
          <React.Suspense
            fallback={
              <>
                {Array(20)
                  .fill(0)
                  .map((idx) => (
                    <PlaybookLineDummy key={idx} dataColumns={dataColumns} />
                  ))}
              </>
            }
          >
            <PlaybooksLines
              queryRef={queryRef}
              paginationOptions={paginationOptions}
              dataColumns={dataColumns}
              setNumberOfElements={helpers.handleSetNumberOfElements}
            />
          </React.Suspense>
        )}
      </ListLines>
    );
  };
  return (
    <div className={classes.container}>
      <ProcessingMenu />
      {isEnterpriseEdition ? (
        <>
          {renderLines()}
          <Security needs={[KNOWLEDGE_KNUPDATE]}>
            <PlaybookCreation paginationOptions={paginationOptions} />
          </Security>
        </>
      ) : (
        <EnterpriseEdition />
      )}
    </div>
  );
};

export default Playbooks;
