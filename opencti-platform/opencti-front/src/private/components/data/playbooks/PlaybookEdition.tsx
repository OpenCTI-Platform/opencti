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
import PlaybookEditionForm, { playbookEditionFormQuery } from '@components/data/playbooks/PlaybookEditionForm';
import Drawer from '@components/common/drawer/Drawer';
import { PlaybookEditionFormQuery } from '@components/data/playbooks/__generated__/PlaybookEditionFormQuery.graphql';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import EditEntityControlledDial from '../../../../components/EditEntityControlledDial';
import { useFormatter } from '../../../../components/i18n';

const PlaybookEdition = ({ id }: { id: string }) => {
  const queryRef = useQueryLoading<PlaybookEditionFormQuery>(playbookEditionFormQuery, { id });
  const { t_i18n } = useFormatter();

  return (
    <Drawer
      title={t_i18n('Update a playbook')}
      controlledDial={EditEntityControlledDial}
    >
      {queryRef && (
        <React.Suspense fallback={<div/>}>
          <PlaybookEditionForm
            queryRef={queryRef}
          />
        </React.Suspense>
      )}
    </Drawer>
  );
};

export default PlaybookEdition;
