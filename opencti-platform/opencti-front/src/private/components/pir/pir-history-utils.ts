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

import { GqlFilterGroup } from '../../../utils/filters/filtersUtils';

export const pirHistoryFilterGroup: GqlFilterGroup = {
  mode: 'and',
  filters: [
    {
      key: ['event_type'],
      values: ['create', 'delete', 'mutation'], // retro-compatibility
    },
    {
      operator: 'not_eq',
      key: ['context_data.entity_type'],
      values: ['indicates'], // don't display indicates relationships events
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
  ],
};

/**
 * Build URI for redirect in news feed or history table.
 * If log is "Entity added in Pir" then redirect to knowledge overview,
 * otherwise redirect to entity page.
 *
 * @param pirId ID of the PIR.
 * @param context Data of the log to generate URI.
 * @returns URI.
 */
export const pirLogRedirectUri = (
  context: {
    readonly entity_id: string | null | undefined
    readonly from_id: string | null | undefined
  } | null | undefined,
) => {
  return `/dashboard/id/${context?.from_id ?? context?.entity_id}`;
};
