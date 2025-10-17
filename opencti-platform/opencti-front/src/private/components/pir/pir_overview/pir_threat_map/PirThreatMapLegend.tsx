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

interface PirThreatMapLegendProps {
  entityTypes: string[]
  onFilter: (entityTypes: string[]) => void
}

const PirThreatMapLegend = ({ entityTypes, onFilter }: PirThreatMapLegendProps) => {
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
      justifyContent: 'center',
      gap: theme.spacing(2),
      fontSize: 12,
      cursor: 'pointer',
    }}
    >
      {entityTypes.map((type) => (
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: theme.spacing(0.5),
            opacity: disabledTypes.includes(type) ? 0.5 : 1,
          }}
          key={type}
          onClick={() => toggleType(type)}
        >
          <div
            style={{
              width: 10,
              height: 10,
              borderRadius: 10,
              background: itemColor(type),
            }}
          />
          <span>{t_i18n(`entity_${type}`)}</span>
        </div>
      ))}
    </div>
  );
};

export default PirThreatMapLegend;
