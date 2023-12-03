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
import FileIndexingMonitoring from '@components/settings/file_indexing/FileIndexingMonitoring';
import {
  graphql,
  PreloadedQuery,
  usePreloadedQuery,
  useQueryLoader,
} from 'react-relay';
import { FileIndexingConfigurationQuery$data } from '@components/settings/file_indexing/__generated__/FileIndexingConfigurationQuery.graphql';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { FileIndexingConfigurationAndMonitoringQuery } from './__generated__/FileIndexingConfigurationAndMonitoringQuery.graphql';

const fileIndexingConfigurationAndMonitoringQuery = graphql`
  query FileIndexingConfigurationAndMonitoringQuery(
    $mimeTypes: [String!]
    $maxFileSize: Float
    $excludedPaths: [String!]
    $includedPaths: [String!]
  ) {
    filesMetrics(
      mimeTypes: $mimeTypes
      maxFileSize: $maxFileSize
      excludedPaths: $excludedPaths
      includedPaths: $includedPaths
    ) {
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
  'text/html',
];
export const fileIndexingDefaultMaxFileSize = 5242880;

interface FileIndexingConfigurationAndMonitoringComponentProps {
  managerConfiguration: FileIndexingConfigurationQuery$data['managerConfigurationByManagerId'];
  queryRef: PreloadedQuery<FileIndexingConfigurationAndMonitoringQuery>;
}

const FileIndexingConfigurationAndMonitoringComponent: FunctionComponent<
FileIndexingConfigurationAndMonitoringComponentProps
> = ({ managerConfiguration, queryRef }) => {
  const { filesMetrics } = usePreloadedQuery<FileIndexingConfigurationAndMonitoringQuery>(
    fileIndexingConfigurationAndMonitoringQuery,
    queryRef,
  );
  const totalFiles = filesMetrics?.globalCount ?? 0;
  const managerConfigurationId = managerConfiguration?.id;
  const lastIndexationDate = managerConfiguration?.last_run_end_date;
  const isStarted = managerConfiguration?.manager_running || false;
  return (
    <div style={{ flexGrow: 1, paddingBottom: 50 }}>
      <FileIndexingMonitoring
        totalFiles={totalFiles}
        isStarted={isStarted}
        managerConfigurationId={managerConfigurationId}
        lastIndexationDate={lastIndexationDate}
        filesMetrics={filesMetrics}
        managerConfiguration={managerConfiguration}
      />
    </div>
  );
};

interface FileIndexingConfigurationAndMonitoringProps {
  managerConfiguration: FileIndexingConfigurationQuery$data['managerConfigurationByManagerId'];
}

const FileIndexingConfigurationAndMonitoring: FunctionComponent<
FileIndexingConfigurationAndMonitoringProps
> = ({ managerConfiguration }) => {
  const [queryRef, loadQuery] = useQueryLoader<FileIndexingConfigurationAndMonitoringQuery>(
    fileIndexingConfigurationAndMonitoringQuery,
  );
  const manager_setting = managerConfiguration?.manager_setting;
  const entityTypes: string[] = manager_setting?.entity_types ?? [];
  const includedPaths = entityTypes.map(
    (entityType) => `import/${entityType}/`,
  );
  if (manager_setting?.include_global_files && includedPaths.length > 0) {
    includedPaths.push('import/global/'); // add global to included paths
  }
  const queryArgs = {
    mimeTypes:
      manager_setting?.accept_mime_types?.length > 0
        ? manager_setting.accept_mime_types
        : fileIndexingDefaultMimeTypes,
    maxFileSize:
      manager_setting?.max_file_size ?? fileIndexingDefaultMaxFileSize,
    excludedPaths: manager_setting?.include_global_files
      ? []
      : ['import/global'],
    includedPaths,
  };
  useEffect(() => {
    loadQuery(queryArgs, { fetchPolicy: 'store-and-network' });
  }, [manager_setting]);
  return (
    <>
      {queryRef && (
        <React.Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <FileIndexingConfigurationAndMonitoringComponent
            queryRef={queryRef}
            managerConfiguration={managerConfiguration}
          />
        </React.Suspense>
      )}
    </>
  );
};

export default FileIndexingConfigurationAndMonitoring;
