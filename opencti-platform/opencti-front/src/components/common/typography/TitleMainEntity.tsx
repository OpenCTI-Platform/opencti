import { PropsWithChildren } from 'react';
import { Typography } from '@mui/material';
import { PropsWithSx } from '../../../utils/props';

type TitleMainEntityProps = PropsWithChildren & PropsWithSx;

const TitleMainEntity = ({ children, sx }: TitleMainEntityProps) => {
  return (
    <Typography
      variant="h1"
      sx={{
        marginBottom: 0,
        lineHeight: '36px',
        fontSize: 28,
        ...sx,
      }}
    >
      {children}
    </Typography>
  );
};

export default TitleMainEntity;
