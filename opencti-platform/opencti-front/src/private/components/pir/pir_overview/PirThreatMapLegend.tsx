import { useTheme } from '@mui/material/styles';
import React, { useState } from 'react';
import type { Theme } from '../../../../components/Theme';
import { itemColor } from '../../../../utils/Colors';

interface PirThreatMapLegendProps {
  entityTypes: string[]
  onFilter: (entityTypes: string[]) => void
}

const PirThreatMapLegend = ({ entityTypes, onFilter }: PirThreatMapLegendProps) => {
  const theme = useTheme<Theme>();
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
          <span>{type}</span>
        </div>
      ))}
    </div>
  );
};

export default PirThreatMapLegend;
