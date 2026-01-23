import { Box, SxProps } from '@mui/material';
import { useTheme } from '@mui/styles';
import Markdown from 'react-markdown';
import { Theme } from '../../../components/Theme';
import { PropsWithSx } from '../../../utils/props';

interface LoginMarkdownProps extends PropsWithSx {
  children?: string | null;
}

const LoginMarkdown = ({ children, sx }: LoginMarkdownProps) => {
  const theme = useTheme<Theme>();

  const markdownStyleOverwrite: SxProps = {
    margin: 0,
    fontSize: 12,
    color: theme.palette.text.light,
  };

  return (
    <Box
      sx={{
        ...sx,
        '& p': markdownStyleOverwrite,
      }}
    >
      <Markdown>{children}</Markdown>
    </Box>
  );
};

export default LoginMarkdown;
