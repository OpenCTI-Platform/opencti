import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import { useTheme } from '@mui/styles';
import React from 'react';
import Card from '../../../../components/common/card/Card';
import CardTitle from '../../../../components/common/card/CardTitle';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';

interface Dependency {
  readonly name: string;
  readonly version: string;
}

interface SettingsDependenciesProps {
  dependencies: ReadonlyArray<Dependency>;
}

const toTestId = (name: string) => name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');

const SettingsDependencies = ({ dependencies }: SettingsDependenciesProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  if (dependencies.length === 0) {
    return null;
  }
  return (
    <section data-testid="settings-dependencies">
      <CardTitle>{t_i18n('Dependencies')}</CardTitle>
      <Box
        sx={{
          display: 'grid',
          // Four fixed columns: a card keeps one width whether three or four services are reported.
          gridTemplateColumns: 'repeat(4, minmax(0, 1fr))',
          gap: 3,
        }}
      >
        {dependencies.map((dependency) => (
          <Card key={dependency.name} padding="medium" data-testid={`settings-dependency-${toTestId(dependency.name)}`}>
            <Typography variant="body2" sx={{ color: theme.palette.text.light, lineHeight: '19px' }}>
              {t_i18n(dependency.name)}
            </Typography>
            <Typography
              variant="body1"
              title={dependency.version}
              sx={{
                marginTop: 0.5,
                fontWeight: 500,
                lineHeight: '24px',
                whiteSpace: 'nowrap',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                '&::first-letter': { textTransform: 'uppercase' },
              }}
            >
              {dependency.version}
            </Typography>
          </Card>
        ))}
      </Box>
    </section>
  );
};

export default SettingsDependencies;
