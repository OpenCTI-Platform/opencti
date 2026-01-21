import { Box, Stack, SxProps } from '@mui/material';
import { useTheme } from '@mui/styles';
import { PropsWithChildren } from 'react';
import { Theme } from '../../../components/Theme';

const LoginLayout = ({ children }: PropsWithChildren) => {
  const theme = useTheme<Theme>();

  const contentSx: SxProps = {
    minWidth: 500,
    background: 'red',
  };

  return (
    <Stack direction="row" height="100%">
      <Box flex={1} sx={contentSx}>content</Box>
      <Box flex={2}>deco</Box>
    </Stack>
  );
};

export default LoginLayout;
