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
import {
  FileIndexingConfigurationQuery$data,
} from '@components/settings/file_indexing/__generated__/FileIndexingConfigurationQuery.graphql';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { FileIndexingConfigurationAndMonitoringQuery } from './__generated__/FileIndexingConfigurationAndMonitoringQuery.graphql';

const fileIndexingConfigurationAndMonitoringQuery = graphql`
  query FileIndexingConfigurationAndMonitoringQuery($mimeTypes: [String!], $maxFileSize: Float, $excludedPaths: [String!]) {
    filesMetrics(mimeTypes: $mimeTypes, maxFileSize: $maxFileSize, excludedPaths: $excludedPaths) {
      globalCount
      globalSize
      metricsByMimeType {
        mimeType
        count
        size
      }
    }
  }
`;

export const fileIndexingDefaultMimeTypes = [
  'application/pdf',
  'text/plain',
  'text/csv',
  'application/vnd.ms-excel',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
];
export const fileIndexingDefaultMaxFileSize = 5242880;

interface FileIndexingConfigurationAndMonitoringComponentProps {
  managerConfiguration: FileIndexingConfigurationQuery$data['managerConfigurationByManagerId']
  queryRef: PreloadedQuery<FileIndexingConfigurationAndMonitoringQuery>;
}

const FileIndexingConfigurationAndMonitoringComponent: FunctionComponent<FileIndexingConfigurationAndMonitoringComponentProps> = ({
  managerConfiguration,
  queryRef,
}) => {
  const { filesMetrics } = usePreloadedQuery<FileIndexingConfigurationAndMonitoringQuery>(fileIndexingConfigurationAndMonitoringQuery, queryRef);
  const totalFiles = filesMetrics?.globalCount ?? 0;
  const managerConfigurationId = managerConfiguration?.id;
  const isStarted = managerConfiguration?.manager_running || false;

  return (
    <Grid container={true} spacing={3}>
      <Grid item={true} xs={6} style={{ marginTop: 30 }}>
        <FileIndexingConfiguration
          filesMetrics={filesMetrics}
          managerConfiguration={managerConfiguration}
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
  managerConfiguration: FileIndexingConfigurationQuery$data['managerConfigurationByManagerId']
}

const FileIndexingConfigurationAndMonitoring: FunctionComponent<FileIndexingConfigurationAndMonitoringProps> = ({
  managerConfiguration,
}) => {
  const [queryRef, loadQuery] = useQueryLoader<FileIndexingConfigurationAndMonitoringQuery>(fileIndexingConfigurationAndMonitoringQuery);
  const manager_setting = managerConfiguration?.manager_setting;
  const queryArgs = {
    mimeTypes: manager_setting?.accept_mime_types ?? fileIndexingDefaultMimeTypes,
    maxFileSize: manager_setting?.max_file_size ?? fileIndexingDefaultMaxFileSize,
    excludedPaths: manager_setting?.include_global_files ? [] : ['import/global'],
  };
  useEffect(() => {
    loadQuery(queryArgs, { fetchPolicy: 'store-and-network' });
  }, [manager_setting]);
  return (
    <>
      {queryRef ? (
        <React.Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <FileIndexingConfigurationAndMonitoringComponent
            queryRef={queryRef}
            managerConfiguration={managerConfiguration}
          />
        </React.Suspense>
      ) : (
        <Loader variant={LoaderVariant.container} />
      )}
    </>
  );
};

export default FileIndexingConfigurationAndMonitoring;
