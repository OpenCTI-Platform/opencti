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

import { graphql, useFragment } from 'react-relay';
import React, { useState } from 'react';
import { Box, Typography } from '@mui/material';
import Button from '@common/button/Button';
import FormAuthorizedMembersDialog from '@components/common/form/FormAuthorizedMembersDialog';
import PirPopover from './PirPopover';
import PirEdition from './pir_form/PirEdition';
import { PirHeaderFragment$key } from './__generated__/PirHeaderFragment.graphql';
import { useFormatter } from '../../../components/i18n';
import Breadcrumbs from '../../../components/Breadcrumbs';
import { PirEditionFragment$key } from './pir_form/__generated__/PirEditionFragment.graphql';
import { authorizedMembersToOptions, useGetCurrentUserAccessRight } from '../../../utils/authorizedMembers';
import { PIRAPI_PIRUPDATE, SETTINGS_SETACCESSES } from '../../../utils/hooks/useGranted';
import Security from '../../../utils/Security';

const headerFragment = graphql`
  fragment PirHeaderFragment on Pir {
    id
    name
    creators {
      id
      name
      entity_type
    }
    currentUserAccessRight
    authorizedMembers {
      id
      name
      entity_type
      access_right
      member_id
      groups_restriction {
        id
        name
      }
    }
    ...PirPopoverFragment
  }
`;

const pirHeaderEditAuthorizedMembersMutation = graphql`
  mutation PirHeaderEditAuthorizedMembersMutation($id: ID!, $input: [MemberAccessInput!]!) {
    pirEditAuthorizedMembers(id: $id, input: $input) {
      ...PirHeaderFragment
    }
  }
`;

interface PirHeaderProps {
  data: PirHeaderFragment$key;
  editionData: PirEditionFragment$key;
}

const PirHeader = ({ data, editionData }: PirHeaderProps) => {
  const { t_i18n } = useFormatter();
  const pir = useFragment(headerFragment, data);
  const { name, id, authorizedMembers, creators, currentUserAccessRight } = pir;
  const { canManage, canEdit } = useGetCurrentUserAccessRight(currentUserAccessRight);

  const [isEditionOpen, setIsEditionOpen] = useState(false);

  const breadcrumb = [
    { label: t_i18n('PIR'), link: '/dashboard/pirs' },
    { label: name, current: true },
  ];

  return (
    <>
      <Breadcrumbs elements={breadcrumb} />

      <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
        <Typography variant="h1" sx={{ marginBottom: 0, flex: 1 }}>
          {name}
        </Typography>

        <Security needs={[PIRAPI_PIRUPDATE]} hasAccess={canEdit}>
          <>
            <div>
              <Security matchAll needs={[PIRAPI_PIRUPDATE, SETTINGS_SETACCESSES]} hasAccess={canManage}>
                <FormAuthorizedMembersDialog
                  id={id}
                  owner={creators?.[0]}
                  mutation={pirHeaderEditAuthorizedMembersMutation}
                  authorizedMembers={authorizedMembersToOptions(authorizedMembers)}
                  canDeactivate={false}
                  customInfoMessage={t_i18n('info_authorizedmembers_pir')}
                />
              </Security>

              <Security needs={[PIRAPI_PIRUPDATE]} hasAccess={canManage}>
                <PirPopover data={pir} />
              </Security>
            </div>

            <Button
              onClick={() => setIsEditionOpen(true)}
              aria-label={t_i18n('Update')}
              title={t_i18n('Update')}
            >
              {t_i18n('Update')}
            </Button>
          </>
        </Security>
      </Box>

      <PirEdition
        isOpen={isEditionOpen}
        onClose={() => setIsEditionOpen(false)}
        data={editionData}
      />
    </>
  );
};

export default PirHeader;
