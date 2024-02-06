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

import googleAnalytics from '@analytics/google-analytics';
import { isNotEmptyField } from '../utils/utils';
import { RootSettings$data } from './__generated__/RootSettings.graphql';

const generateAnalyticsConfig = (settings: RootSettings$data) => {
  const isEnterpriseEdition = isNotEmptyField(settings.enterprise_edition);
  const googleMeasurement = settings.analytics_google_analytics_v4;
  return {
    app: 'opencti',
    plugins: [
      googleAnalytics({
        measurementIds: [googleMeasurement],
        enabled: isEnterpriseEdition && !!googleMeasurement,
      }),
    ],
  };
};

export default generateAnalyticsConfig;
