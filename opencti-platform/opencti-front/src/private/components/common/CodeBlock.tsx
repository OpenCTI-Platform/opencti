import React, { FunctionComponent } from 'react';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { a11yDark, coy } from 'react-syntax-highlighter/dist/esm/styles/prism';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../../components/Theme';

interface CodeBlockProps {
  code: string;
  language: string;
  customHeight?: string;
}

const CodeBlock: FunctionComponent<CodeBlockProps> = ({ language, code, customHeight = '400px' }) => {
  const theme = useTheme<Theme>();
  return (
    <SyntaxHighlighter
      language={language}
      style={theme.palette.mode === 'dark' ? a11yDark : coy}
      customStyle={{ height: customHeight, minWidth: '550px' }}
      showLineNumbers
    >
      {code}
    </SyntaxHighlighter>
  );
};

export default CodeBlock;
