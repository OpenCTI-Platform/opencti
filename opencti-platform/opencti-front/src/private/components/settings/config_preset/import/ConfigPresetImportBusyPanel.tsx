import React, { FunctionComponent, ReactNode } from 'react';
import { useTheme } from '@mui/material/styles';
import { Text } from '@filigran/design-system';
import type { Theme } from '../../../../../components/Theme';

interface ConfigPresetImportBusyPanelProps {
  title: string;
  children: ReactNode;
}

// What a bundle is doing, in the place under the upload field: its title, then its progress or what the user can do meanwhile
const ConfigPresetImportBusyPanel: FunctionComponent<ConfigPresetImportBusyPanelProps> = ({ title, children }) => {
  const theme = useTheme<Theme>();
  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: theme.spacing(1.5),
        padding: theme.spacing(2),
        borderRadius: theme.borderRadius,
        background: theme.palette.background.default,
      }}
    >
      <Text variant="title-sm">{title}</Text>
      {children}
    </div>
  );
};

export default ConfigPresetImportBusyPanel;
