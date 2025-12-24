import { CSSProperties, PropsWithChildren, ReactNode } from 'react';
import { useTheme } from '@mui/material/styles';
import { Stack } from '@mui/material';
import type { Theme } from '../../../../components/Theme';
import Card from '../../../../components/common/card/Card';

interface RulesHeaderGridCardProps extends PropsWithChildren {
  title: string;
  icon: ReactNode;
}

const RulesHeaderGridCard = ({
  title,
  children,
  icon,
}: RulesHeaderGridCardProps) => {
  const theme = useTheme<Theme>();

  const styleIcon: CSSProperties = {
    color: theme.palette.primary.main,
  };

  return (
    <Card title={title}>
      <Stack
        direction="row"
        alignItems="center"
        justifyContent="space-between"
      >
        {children}
        <div style={styleIcon}>{icon}</div>
      </Stack>
    </Card>
  );
};

export default RulesHeaderGridCard;
