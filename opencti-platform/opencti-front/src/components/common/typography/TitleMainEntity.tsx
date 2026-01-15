import { PropsWithChildren } from 'react';
import { Typography } from '@mui/material';
import { PropsWithSx } from '../../../utils/props';

type TitleMainEntityProps = {
  preserveCase?: boolean;
} & PropsWithChildren & PropsWithSx;

const TitleMainEntity = ({ children, sx, preserveCase = false }: TitleMainEntityProps) => {
  return (
    <Typography
      variant="h1"
      sx={{
        marginBottom: 0,
        lineHeight: '36px',
        fontSize: 28,
        ...(preserveCase && {
          textTransform: 'none',
          '&::first-letter': {
            textTransform: 'none',
          },
        }),
        ...sx,
      }}
    >
      {children}
    </Typography>
  );
};

export default TitleMainEntity;
