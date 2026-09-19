/*
Copyright (c) 2021-2025 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import React, { ReactNode } from 'react';
import type { WidgetHost } from '../../utils/widget/widget';
import useGranted, { SETTINGS_SECURITYACTIVITY, SETTINGS_SETACCESSES, VIRTUAL_ORGANIZATION_ADMIN } from 'src/utils/hooks/useGranted';
import useEnterpriseEdition from 'src/utils/hooks/useEnterpriseEdition';
import WidgetRenderContent from 'src/components/dashboard/WidgetRenderContent';

interface AuditsWidgetRenderContentParams {
  isMissingHostEntity: boolean;
  isMissingSavedFilters: boolean;
  queryRef: unknown;
  host?: WidgetHost;
  children: ReactNode;
}

/**
 * Renders the common guard checks for audits widgets.
 * Returns the appropriate fallback component if a guard condition is met,
 * or wraps the children in a Suspense boundary when the queryRef is ready.
 */
const AuditsWidgetRenderContent = ({
  isMissingHostEntity,
  isMissingSavedFilters,
  queryRef,
  host,
  children,
}: AuditsWidgetRenderContentParams) => {
  const isGrantedToSettings = useGranted([SETTINGS_SETACCESSES, SETTINGS_SECURITYACTIVITY, VIRTUAL_ORGANIZATION_ADMIN]);
  const isEnterpriseEdition = useEnterpriseEdition();

  return (
    <WidgetRenderContent
      isMissingHostEntity={isMissingHostEntity}
      isMissingSavedFilters={isMissingSavedFilters}
      isGranted={isGrantedToSettings && isEnterpriseEdition}
      queryRef={queryRef}
      host={host}
    >
      {children}
    </WidgetRenderContent>
  );
};

export default AuditsWidgetRenderContent;
