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

import { GqlFilterGroup, sanitizeFilterGroupKeysForFrontend } from '../../../utils/filters/filtersUtils';

export const pirHistoryFilterGroup = (pirId: string): GqlFilterGroup => {
  return {
    mode: 'and',
    filters: [
      {
        key: ['event_type'],
        values: ['create', 'delete', 'mutation'], // retro-compatibility
      },
    ],
    filterGroups: [
      {
        mode: 'or',
        filters: [
          {
            key: ['event_scope'],
            values: ['create', 'delete', 'update'],
          },
          {
            key: ['event_scope'],
            values: [], // if event_scope is null, event_type is not
            operator: 'nil',
          },
        ],
        filterGroups: [],
      },
      {
        mode: 'or',
        filters: [
          {
            key: ['context_data.pir_ids'],
            values: [pirId],
          },
        ],
        filterGroups: [],
      },
      {
        mode: 'or',
        filters: [
          {
            operator: 'not_eq',
            key: ['context_data.entity_type'],
            values: ['indicates'],
          },
        ],
        filterGroups: [],
      },
    ],
  };
};

export const pirLogRedirectUri = (
  pirId: string,
  context: {
    readonly entity_id: string | null | undefined
    readonly entity_name: string | null | undefined
    readonly entity_type: string | null | undefined
    readonly message: string
  } | null | undefined,
) => {
  const isAddInPir = /adds .+ in `In PIR`/.test(context?.message ?? '');
  let redirectURI = `/dashboard/id/${context?.entity_id}`;
  if (isAddInPir && context?.entity_id) {
    const filter = encodeURIComponent(JSON.stringify(sanitizeFilterGroupKeysForFrontend({
      mode: 'and',
      filters: [{
        key: ['fromId'],
        values: [context.entity_id],
      }],
      filterGroups: [],
    })));
    redirectURI = `/dashboard/pirs/${pirId}/threats?filters=${filter}`;
  }
  return redirectURI;
};
