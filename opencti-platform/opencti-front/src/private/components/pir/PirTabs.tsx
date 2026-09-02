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

import React from 'react';
import { Tabs, TabsList, TabsTrigger } from '@filigran/design-system';
import { Link, useLocation } from 'react-router-dom';
import { graphql, useFragment } from 'react-relay';
import { useFormatter } from '../../../components/i18n';
import { PirTabsFragment$key } from './__generated__/PirTabsFragment.graphql';

const tabsFragment = graphql`
  fragment PirTabsFragment on Pir {
    id
  }
`;

interface PirTabsProps {
  data: PirTabsFragment$key;
}

const PirTabs = ({ data }: PirTabsProps) => {
  const { id } = useFragment(tabsFragment, data);
  const { pathname } = useLocation();
  const { t_i18n } = useFormatter();

  let current = 'overview';
  if (pathname.endsWith('threats')) current = 'threats';
  if (pathname.endsWith('analyses')) current = 'analyses';
  if (pathname.endsWith('activities')) current = 'activities';

  return (
    <Tabs value={current} panels="external">
      <TabsList className="mb-6">
        <TabsTrigger value="overview" asChild>
          <Link to={`/dashboard/pirs/${id}`}>{t_i18n('Overview')}</Link>
        </TabsTrigger>
        <TabsTrigger value="threats" asChild>
          <Link to={`/dashboard/pirs/${id}/threats`}>{t_i18n('Threats')}</Link>
        </TabsTrigger>
        <TabsTrigger value="analyses" asChild>
          <Link to={`/dashboard/pirs/${id}/analyses`}>{t_i18n('Analyses')}</Link>
        </TabsTrigger>
        <TabsTrigger value="activities" asChild>
          <Link to={`/dashboard/pirs/${id}/activities`}>{t_i18n('Activities')}</Link>
        </TabsTrigger>
      </TabsList>
    </Tabs>
  );
};

export default PirTabs;
