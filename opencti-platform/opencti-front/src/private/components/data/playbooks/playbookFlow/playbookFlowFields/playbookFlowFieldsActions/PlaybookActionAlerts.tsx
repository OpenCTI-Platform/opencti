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

import { Alert } from '@mui/material';
import { useFormatter } from '../../../../../../../components/i18n';
import { PlaybookUpdateAction } from './playbookAction-types';

interface ActionAlertsProps {
  action: PlaybookUpdateAction
}

const PlaybookActionAlerts = ({ action }: ActionAlertsProps) => {
  const { t_i18n } = useFormatter();

  return (
    <>
      {(action.op === 'replace' && ['objectMarking', 'objectLabel', 'objectAssignee', 'objectParticipant'].includes(action.attribute ?? '')) && (
        <Alert severity="warning" style={{ marginBottom: 20 }}>
          {t_i18n('Replace operation will effectively replace this field values added in the context of this playbook such as enrichment or other knowledge manipulations but it will only append them if values are already written in the platform.')}
        </Alert>
      )}
      {(action.op === 'replace' && action.attribute === 'createdBy') && (
        <Alert severity="warning" style={{ marginBottom: 20 }}>
          {t_i18n('Replace operation will effectively replace the author if the confidence level of the entity with the new author is superior to the one of the entity with the old author.')}
        </Alert>
      )}
      {(action.op === 'remove') && (
        <Alert severity="warning" style={{ marginBottom: 20 }}>
          {t_i18n('Remove operation will only apply on field values added in the context of this playbook such as enrichment or other knowledge manipulations but not if values are already written in the platform.')}
        </Alert>
      )}
    </>
  );
};

export default PlaybookActionAlerts;
