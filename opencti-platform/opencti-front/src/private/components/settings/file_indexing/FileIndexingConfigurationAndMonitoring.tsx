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
import React, { FunctionComponent, useEffect } from 'react';
import Grid from '@mui/material/Grid';
import FileIndexingConfiguration from '@components/settings/file_indexing/FileIndexingConfiguration';
import FileIndexingMonitoring from '@components/settings/file_indexing/FileIndexingMonitoring';
import { graphql, PreloadedQuery, usePreloadedQuery, useQueryLoader } from 'react-relay';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { FileIndexingConfigurationAndMonitoringQuery } from './__generated__/FileIndexingConfigurationAndMonitoringQuery.graphql';

const fileIndexingConfigurationAndMonitoringQuery = graphql`
  query FileIndexingConfigurationAndMonitoringQuery($mimeTypes: [String!], $maxFileSize: Float, $excludedPaths: [String!]) {
    filesMetrics(mimeTypes: $mimeTypes, maxFileSize: $maxFileSize, excludedPaths: $excludedPaths) {
      globalCount
      globalSize
    }
  }
`;

interface FileIndexingConfigurationAndMonitoringComponentProps {
  managerConfigurationByManagerId: {
    id: string;
    last_run_end_date: any;
    last_run_start_date: any;
    manager_id: string;
    manager_running: boolean | null;
    manager_settings: any;
  }
  queryRef: PreloadedQuery<FileIndexingConfigurationAndMonitoringQuery>;
}

const FileIndexingConfigurationAndMonitoringComponent: FunctionComponent<FileIndexingConfigurationAndMonitoringComponentProps> = ({
  managerConfigurationByManagerId,
  queryRef,
}) => {
  const { filesMetrics } = usePreloadedQuery<FileIndexingConfigurationAndMonitoringQuery>(fileIndexingConfigurationAndMonitoringQuery, queryRef);
  const totalFiles = filesMetrics?.globalCount ?? 0;
  const dataToIndex = filesMetrics?.globalSize ?? 0;
  const managerConfigurationId = managerConfigurationByManagerId?.id;
  const isStarted = managerConfigurationByManagerId?.manager_running || false;

  return (
    <Grid container={true} spacing={3}>
      <Grid item={true} xs={6} style={{ marginTop: 30 }}>
        <FileIndexingConfiguration
          totalFiles={totalFiles}
          dataToIndex={dataToIndex}
        />
      </Grid>
      <Grid item={true} xs={6} style={{ marginTop: 30 }}>
        <FileIndexingMonitoring
          totalFiles={totalFiles}
          isStarted={isStarted}
          managerConfigurationId={managerConfigurationId}
        />
      </Grid>
    </Grid>
  );
};

interface FileIndexingConfigurationAndMonitoringProps {
  managerConfigurationByManagerId: {
    id: string;
    last_run_end_date: any;
    last_run_start_date: any;
    manager_id: string;
    manager_running: boolean | null;
    manager_settings: any;
  }
}

const FileIndexingConfigurationAndMonitoring: FunctionComponent<FileIndexingConfigurationAndMonitoringProps> = ({
  managerConfigurationByManagerId,
}) => {
  const [queryRef, loadQuery] = useQueryLoader<FileIndexingConfigurationAndMonitoringQuery>(fileIndexingConfigurationAndMonitoringQuery);
  // TODO MVP2 : get from configuration
  const defaultMimeTypes = ['application/pdf', 'text/plain', 'text/csv', 'application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'];
  const queryArgs = {
    mimeTypes: defaultMimeTypes,
    maxFileSize: 5242880,
    excludedPaths: ['import/global'],
  };
  useEffect(() => {
    loadQuery(queryArgs, { fetchPolicy: 'store-and-network' });
  }, []);
  return (
    <>
      {queryRef ? (
        <React.Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <FileIndexingConfigurationAndMonitoringComponent
            queryRef={queryRef}
            managerConfigurationByManagerId={managerConfigurationByManagerId}
          />
        </React.Suspense>
      ) : (
        <Loader variant={LoaderVariant.container} />
      )}
    </>
  );
};

export default FileIndexingConfigurationAndMonitoring;
