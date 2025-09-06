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
import MarkdownDisplay from '../../../components/MarkdownDisplay';
import { displayEntityTypeForTranslation } from '../../../utils/String';
import { isNotEmptyField } from '../../../utils/utils';
import { useFormatter } from '../../../components/i18n';

export interface PirLog {
  readonly context_data: {
    readonly entity_id: string | null | undefined;
    readonly from_id: string | null | undefined;
    readonly entity_name: string | null | undefined;
    readonly entity_type: string | null | undefined;
    readonly message: string;
    readonly pir_score: number | null | undefined;
  } | null | undefined;
  readonly entity_type: string | null | undefined;
  readonly event_scope: string | null | undefined;
  readonly user: {
    readonly name: string;
  } | null | undefined;
}

interface PirHistoryMessageProps {
  log: PirLog
  pirName: string
}

const PirHistoryMessage = ({ log }: PirHistoryMessageProps) => {
  const { t_i18n } = useFormatter();
  const { context_data, event_scope, user } = log;

  const getHistoryMessage = () => {
    const message = context_data?.message ?? '';
    const entityType = t_i18n(displayEntityTypeForTranslation(context_data?.entity_type ?? ''));

    const isUpdate = event_scope === 'update' && isNotEmptyField(context_data?.entity_name);

    if (context_data?.entity_type === 'in-pir') {
      if (event_scope === 'create') {
        return `${message} (score: ${context_data?.pir_score})`;
      }
      if (isUpdate) {
        return `${message} for \`${context_data?.entity_name?.split('in-pir')[0]}\``;
      }
      return message;
    }

    // Default message
    return `\`${user?.name}\` ${message} ${isUpdate ? `for \`${context_data?.entity_name}\` (${entityType})` : ''}`;
  };

  return (
    <MarkdownDisplay
      commonmark
      remarkGfmPlugin
      content={getHistoryMessage()}
    />
  );
};

export default PirHistoryMessage;
