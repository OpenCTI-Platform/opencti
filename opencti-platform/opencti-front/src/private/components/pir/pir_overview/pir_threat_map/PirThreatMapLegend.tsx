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

import { useTheme } from '@mui/material/styles';
import React, { useState } from 'react';
import type { Theme } from '../../../../../components/Theme';
import { itemColor } from '../../../../../utils/Colors';
import { useFormatter } from '../../../../../components/i18n';
import { onActivationKey } from '../../../../../utils/domEvent';
import { PirThreatMapTypeStyle } from './pirThreatMapUtils';
import PirThreatMapShape from './PirThreatMapShape';

interface PirThreatMapLegendProps {
  entityTypes: string[];
  onFilter: (entityTypes: string[]) => void;
  // Colour and shape of each type as the map draws it.
  typeStyles?: Record<string, PirThreatMapTypeStyle>;
  // Entities per type on the map, shown next to the label.
  counts?: Record<string, number>;
}

const PirThreatMapLegend = ({ entityTypes, onFilter, typeStyles, counts }: PirThreatMapLegendProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const [disabledTypes, setDisabledTypes] = useState<string[]>([]);

  const toggleType = (type: string) => {
    const alreadyDisabled = disabledTypes.includes(type);
    let newDisabledTypes = disabledTypes.filter((t) => t !== type);
    if (!alreadyDisabled) newDisabledTypes = [...disabledTypes, type];
    setDisabledTypes(newDisabledTypes);
    onFilter(entityTypes.filter((t) => !newDisabledTypes.includes(t)));
  };

  return (
    <div style={{
      display: 'flex',
      flexWrap: 'wrap',
      justifyContent: 'center',
      gap: theme.spacing(1.5),
      fontSize: 12,
      cursor: 'pointer',
    }}
    >
      {entityTypes.map((type) => {
        const style = typeStyles?.[type];
        const count = counts?.[type];
        return (
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: theme.spacing(0.5),
              opacity: disabledTypes.includes(type) ? 0.4 : 1,
              textDecoration: disabledTypes.includes(type) ? 'line-through' : 'none',
            }}
            key={type}
            onClick={() => toggleType(type)}
            role="button"
            tabIndex={0}
            // Opacity alone shows whether the type is on the map: expose it too
            aria-pressed={!disabledTypes.includes(type)}
            onKeyDown={onActivationKey(() => toggleType(type))}
          >
            <PirThreatMapShape
              shape={style?.shape ?? 'circle'}
              color={style?.color ?? itemColor(type)}
              size={10}
            />
            <span>{t_i18n(`entity_${type}`)}</span>
            {count !== undefined && (
              <span aria-hidden="true" style={{ color: theme.palette.text?.secondary }}>{count}</span>
            )}
          </div>
        );
      })}
    </div>
  );
};

export default PirThreatMapLegend;
