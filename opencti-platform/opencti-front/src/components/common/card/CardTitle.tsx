import { CSSProperties, PropsWithChildren, ReactNode } from 'react';
import { Stack, SxProps, Typography } from '@mui/material';
import { useTheme } from '@mui/styles';
import { Theme } from '../../Theme';

interface CardTitleProps extends PropsWithChildren {
  action?: ReactNode;
  alignItems?: CSSProperties['alignItems'];
  sx?: SxProps;
}

const CardTitle = ({
  children,
  alignItems = 'center',
  action,
  sx = {},
}: CardTitleProps) => {
  const theme = useTheme<Theme>();

  const containerSx: SxProps = {
    height: alignItems !== 'center' ? 'inherit' : '19px',
    marginBottom: theme.spacing(1),
    flex: 0,
    ...sx,
  };

  const titleSx: SxProps = {
    marginBottom: 0,
    textTransform: 'capitalize',
    color: theme.palette.text.light,
    lineHeight: '19px',
    fontSize: '12px',
    fontWeight: 400,
    fontFamily: '"IBM Plex Sans", sans-serif',
  };

  return (
    <Stack
      direction="row"
      sx={[{
        justifyContent: 'space-between',
        alignItems: alignItems,
      }, ...(Array.isArray(containerSx) ? containerSx : [containerSx])]}
    >
      <Typography variant="h5" sx={titleSx}>
        {children}
      </Typography>
      <Stack
        direction="row"
        sx={{
          gap: 1,
        }}
      >
        {action}
      </Stack>
    </Stack>
  );
};

export default CardTitle;
