import React from 'react';
import { useTheme } from '@mui/styles';
import { Text } from '@filigran/design-system';
import type { Theme } from '../../../components/Theme';

/** The title of a section of the hunt creation and edition forms. */
const HuntFormSectionTitle = ({ children }: { children: React.ReactNode }) => {
  const theme = useTheme<Theme>();
  return (
    <Text variant="title-sm" as="h3" style={{ marginTop: theme.spacing(4), marginBottom: 0 }}>
      {children}
    </Text>
  );
};

export default HuntFormSectionTitle;
