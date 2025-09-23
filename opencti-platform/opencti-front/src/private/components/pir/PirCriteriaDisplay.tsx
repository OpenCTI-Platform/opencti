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

import React, { PropsWithChildren } from 'react';
import { PreloadedQuery, usePreloadedQuery } from 'react-relay';
import Chip, { ChipProps } from '@mui/material/Chip';
import Tooltip from '@mui/material/Tooltip';
import { useTheme } from '@mui/material/styles';
import { FilterGroup } from '../../../utils/filters/filtersHelpers-types';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { FilterValuesContentQuery } from '../../../components/__generated__/FilterValuesContentQuery.graphql';
import { filterValuesContentQuery } from '../../../components/FilterValuesContent';
import { GqlFilterGroup, removeIdFromFilterGroupObject } from '../../../utils/filters/filtersUtils';
import { useFormatter } from '../../../components/i18n';
import type { Theme } from '../../../components/Theme';

interface PirFiltersDisplayComponentProps extends PropsWithChildren {
  size?: ChipProps['size']
  full?: boolean
  criteria: FilterGroup[]
  queryRef: PreloadedQuery<FilterValuesContentQuery>
}

const PirCriteriaDisplayComponent = ({
  queryRef,
  criteria,
  full = false,
  size = 'medium',
  children,
}: PirFiltersDisplayComponentProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const { filtersRepresentatives } = usePreloadedQuery(filterValuesContentQuery, queryRef);

  const data = Object.values(Object.groupBy(criteria.flatMap(({ filters }) => {
    const relationship = filters.find((filter) => filter.key.includes('entity_type'))?.values[0];
    const targetId = filters.find((filter) => filter.key.includes('toId'))?.values[0];
    const target = filtersRepresentatives.find((rep) => rep.id === targetId)?.value;
    if (!relationship || !target) return [];
    return { relationship, target };
  }), ({ relationship }) => relationship));

  return (
    <div style={{ display: 'flex', gap: theme.spacing(1) }}>
      {data.flatMap((relationships, i) => {
        if (!relationships || relationships?.length === 0) return [];
        const { relationship } = relationships[0];
        const targets = relationships.map((r) => r.target);
        const shortTargets = targets.slice(0, 2);
        const fullTargetsStr = `${t_i18n(`relationship_${relationship}`)}: ${targets.join(', ')}`;
        let shortTargetsStr = `${t_i18n(`relationship_${relationship}`)}: ${shortTargets.join(', ')}`;
        const lengthDiff = targets.length - shortTargets.length;
        if (lengthDiff > 0) shortTargetsStr += `... +${lengthDiff}`;

        return (
          <Tooltip
            key={i}
            title={fullTargetsStr}
            slotProps={{
              tooltip: {
                sx: {
                  textTransform: 'capitalize',
                  backgroundColor: 'black',
                },
              },
            }}
          >
            {children ? <div>{children}</div> : (
              <Chip
                size={size}
                sx={{ textTransform: 'capitalize', borderRadius: 1, whiteSpace: 'wrap' }}
                label={full ? fullTargetsStr : shortTargetsStr}
              />
            )}
          </Tooltip>
        );
      })}
    </div>
  );
};

type PirCriteriaDisplayProps = Omit<PirFiltersDisplayComponentProps, 'queryRef'>;

const PirCriteriaDisplay = ({ criteria, ...props }: PirCriteriaDisplayProps) => {
  const filters = removeIdFromFilterGroupObject({
    mode: 'and',
    filters: [],
    filterGroups: criteria,
  });
  if (!filters) return null;

  const filtersRepresentativesQueryRef = useQueryLoading<FilterValuesContentQuery>(
    filterValuesContentQuery,
    { filters: filters as unknown as GqlFilterGroup },
  );

  return filtersRepresentativesQueryRef && (
  <PirCriteriaDisplayComponent
    {...props}
    criteria={criteria}
    queryRef={filtersRepresentativesQueryRef}
  />
  );
};

export default PirCriteriaDisplay;
