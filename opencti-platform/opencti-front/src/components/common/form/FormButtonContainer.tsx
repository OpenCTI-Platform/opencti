import { Stack } from '@mui/material';
import { PropsWithChildren } from 'react';

const FormButtonContainer = ({ children }: PropsWithChildren) => {
  return (
    <Stack
      direction="row"
      sx={{
        gap: 1,
        mt: 4,
        justifyContent: 'flex-end',
      }}
    >
      {children}
    </Stack>
  );
};

export default FormButtonContainer;
