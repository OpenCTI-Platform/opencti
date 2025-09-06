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
import { Box, Tab, Tabs } from '@mui/material';
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
  data: PirTabsFragment$key
}

const PirTabs = ({ data }: PirTabsProps) => {
  const { id } = useFragment(tabsFragment, data);
  const { pathname } = useLocation();
  const { t_i18n } = useFormatter();

  let index = 0;
  if (pathname.endsWith('threats')) index = 1;
  if (pathname.endsWith('analyses')) index = 2;
  if (pathname.endsWith('activities')) index = 3;

  return (
    <Box sx={{
      borderBottom: 1,
      borderColor: 'divider',
      marginBottom: 3,
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
    }}
    >
      <Tabs value={index}>
        <Tab
          component={Link}
          label={t_i18n('Overview')}
          to={`/dashboard/pirs/${id}`}
        />
        <Tab
          component={Link}
          label={t_i18n('Threats')}
          to={`/dashboard/pirs/${id}/threats`}
        />
        <Tab
          component={Link}
          label={t_i18n('Analyses')}
          to={`/dashboard/pirs/${id}/analyses`}
        />
        <Tab
          component={Link}
          label={t_i18n('Activities')}
          to={`/dashboard/pirs/${id}/activities`}
        />
      </Tabs>
    </Box>
  );
};

export default PirTabs;
