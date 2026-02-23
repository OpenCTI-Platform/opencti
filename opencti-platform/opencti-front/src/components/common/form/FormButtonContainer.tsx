import { Stack } from '@mui/material';
import { PropsWithChildren } from 'react';

const FormButtonContainer = ({ children }: PropsWithChildren) => {
  return (
    <Stack
      direction="row"
      gap={1}
      sx={{ mt: 4, justifyContent: 'flex-end' }}
    >
      {children}
    </Stack>
  );
};

export default FormButtonContainer;
