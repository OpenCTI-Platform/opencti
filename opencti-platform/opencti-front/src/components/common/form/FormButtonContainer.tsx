import { Stack } from '@mui/material';
import { PropsWithChildren } from 'react';

const FormButtonContainer = ({ children }: PropsWithChildren) => {
  return (
    <Stack
      direction="row"
      gap={1}
      justifySelf="flex-end"
      sx={{ mt: 4 }}
    >
      {children}
    </Stack>
  );
};

export default FormButtonContainer;
