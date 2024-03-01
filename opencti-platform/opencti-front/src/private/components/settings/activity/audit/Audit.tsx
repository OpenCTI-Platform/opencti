/*
Copyright (c) 2021-2024 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Non-Commercial License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import React, { useRef, useState, useEffect } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import Checkbox from '@mui/material/Checkbox';
import FormControlLabel from '@mui/material/FormControlLabel';
import Alert from '@mui/material/Alert';
import { CSVLink } from 'react-csv';
import { graphql } from 'react-relay';
import ActivityMenu from '../../ActivityMenu';
import type { Theme } from '../../../../../components/Theme';
import ListLines from '../../../../../components/list_lines/ListLines';
import { usePaginationLocalStorage } from '../../../../../utils/hooks/useLocalStorage';
import useEntityToggle from '../../../../../utils/hooks/useEntityToggle';
import { AuditLinesPaginationQuery, AuditLinesPaginationQuery$variables } from './__generated__/AuditLinesPaginationQuery.graphql';
import useQueryLoading from '../../../../../utils/hooks/useQueryLoading';
import AuditLines, { AuditLinesQuery } from './AuditLines';
import { AuditLine_node$data } from './__generated__/AuditLine_node.graphql';
import { AuditLineDummy } from './AuditLine';
import useAuth from '../../../../../utils/hooks/useAuth';
import { useFormatter } from '../../../../../components/i18n';
import { emptyFilterGroup } from '../../../../../utils/filters/filtersUtils';
import { fetchQuery } from '../../../../../relay/environment';
import Breadcrumbs from '../../../../../components/Breadcrumbs';

const useStyles = makeStyles<Theme>(() => ({
  container: {
    margin: 0,
    padding: '0 200px 50px 0',
  },
}));

const LOCAL_STORAGE_KEY = 'audit';

export const AuditCSVQuery = graphql`
  query AuditCSVQuery(
    $search: String
    $types: [String!]
    $first: Int
    $orderBy: LogsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    audits(
      search: $search
      types: $types
      first: $first
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) {
      edges {
        node {
          id
          entity_type
          event_type
          event_scope
          event_status
          timestamp
          context_uri
          user {
            id
            name
          }
          context_data {
            entity_id
            entity_type
            entity_name
            message
          }
        }
      }
    }
  }
`;

const Audit = () => {
  const classes = useStyles();
  const csvLink = useRef<
  CSVLink & HTMLAnchorElement & { link: HTMLAnchorElement }
  >(null);
  const hasPageRendered = useRef(false);
  const [loading, setLoading] = useState(true);
  const [data, setData] = useState([]);
  const { settings } = useAuth();
  const { t_i18n } = useFormatter();
  const {
    viewStorage,
    paginationOptions,
    helpers: storageHelpers,
  } = usePaginationLocalStorage<AuditLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      numberOfElements: { number: 0, symbol: '', original: 0 },
      filters: emptyFilterGroup,
      searchTerm: '',
      sortBy: 'timestamp',
      orderAsc: false,
      openExports: false,
      types: ['Activity'],
      count: 25,
    },
  );
  const { numberOfElements, filters, searchTerm, sortBy, orderAsc, types } = viewStorage;
  const { selectedElements, deSelectedElements, selectAll, onToggleEntity } = useEntityToggle<AuditLine_node$data>(LOCAL_STORAGE_KEY);
  const dataColumns = {
    timestamp: {
      label: 'Timestamp',
      width: '15%',
      isSortable: true,
    },
    user: {
      label: 'User',
      width: '15%',
      isSortable: false,
    },
    event_type: {
      label: 'Event type',
      width: '10%',
      isSortable: true,
    },
    event_scope: {
      label: 'Event scope',
      width: '10%',
      isSortable: true,
    },
    message: {
      label: 'Message',
      width: '50%',
      isSortable: false,
    },
  };
  const queryRef = useQueryLoading<AuditLinesPaginationQuery>(
    AuditLinesQuery,
    paginationOptions,
  );
  useEffect(() => {
    if (!loading && hasPageRendered.current) {
      csvLink?.current?.link?.click();
    }
    hasPageRendered.current = true;
  }, [loading]);
  const handleExportCsv = async () => {
    setLoading(true);
    await fetchQuery(AuditCSVQuery, { ...paginationOptions, first: 5000 })
      .toPromise()
      .then((result) => {
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-ignore
        const { audits } = result;
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-ignore
        const csvData = audits.edges.map((n) => {
          const { node } = n;
          return {
            id: node.id,
            entity_type: node.entity_type,
            event_type: node.event_type,
            event_scope: node.event_scope,
            event_status: node.event_status,
            timestamp: node.timestamp,
            context_uri: node.context_uri,
            user_id: node.user?.id ?? 'undefined',
            user_name: node.user?.name ?? 'undefined',
            context_data_id: node.context_data?.entity_id ?? 'undefined',
            context_data_entity_type:
              node.context_data?.entity_type ?? 'undefined',
            context_data_entity_name:
              node.context_data?.entity_name ?? 'undefined',
            context_data_message: node.context_data?.message ?? 'undefined',
          };
        });
        setData(csvData);
        setLoading(false);
      });
  };
  const extraFields = (
    <div style={{ marginLeft: 10 }}>
      <FormControlLabel
        value="start"
        control={
          <Checkbox
            style={{ padding: 7 }}
            onChange={() => {
              const newTypes = types?.length === 1 ? ['History', 'Activity'] : ['Activity'];
              storageHelpers.handleAddProperty('types', newTypes);
            }}
            checked={types?.length === 2}
          />
        }
        label="Include knowledge"
        labelPlacement="end"
      />
    </div>
  );
  return (
    <div className={classes.container}>
      <ActivityMenu />
      <Breadcrumbs variant="list" elements={[{ label: t_i18n('Settings') }, { label: t_i18n('Activity') }, { label: t_i18n('Events'), current: true }]} />
      {settings.platform_demo && (
        <Alert severity="info" variant="outlined" style={{ marginBottom: 30 }}>
          {t_i18n(
            'This platform is running in demo mode, all names in the activity and audit logs are redacted.',
          )}
        </Alert>
      )}
      <ListLines
        helpers={storageHelpers}
        sortBy={sortBy}
        orderAsc={orderAsc}
        dataColumns={dataColumns}
        handleSort={storageHelpers.handleSort}
        handleSearch={storageHelpers.handleSearch}
        handleAddFilter={storageHelpers.handleAddFilter}
        handleRemoveFilter={storageHelpers.handleRemoveFilter}
        handleSwitchGlobalMode={storageHelpers.handleSwitchGlobalMode}
        handleSwitchLocalMode={storageHelpers.handleSwitchLocalMode}
        selectAll={selectAll}
        extraFields={extraFields}
        keyword={searchTerm}
        filters={filters}
        paginationOptions={paginationOptions}
        numberOfElements={numberOfElements}
        handleExportCsv={handleExportCsv}
        entityTypes={['History']}
      >
        {queryRef && (
          <React.Suspense
            fallback={
              <>
                {Array(20)
                  .fill(0)
                  .map((_, idx) => (
                    <AuditLineDummy key={idx} dataColumns={dataColumns} />
                  ))}
              </>
            }
          >
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
      <CSVLink filename={`${t_i18n('Audit logs')}.csv`} ref={csvLink} data={data} />
    </div>
  );
};

export default Audit;
