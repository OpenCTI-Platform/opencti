import React, { FunctionComponent } from 'react';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { a11yDark, coy } from 'react-syntax-highlighter/dist/esm/styles/prism';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../../components/Theme';

interface CodeBlockProps {
  code: string;
  language: string;
  customHeight?: string;
  // Height beyond which the block scrolls vertically, none by default
  maxHeight?: string;
  // Wrap the long lines instead of scrolling horizontally
  wrapLongLines?: boolean;
  // Number the lines, true by default
  showLineNumbers?: boolean;
}

const CodeBlock: FunctionComponent<CodeBlockProps> = ({ language, code, customHeight = '400px', maxHeight, wrapLongLines = false, showLineNumbers = true }) => {
  const theme = useTheme<Theme>();
  const highlightStyle = theme.palette.mode === 'dark' ? a11yDark : coy;
  return (
    <SyntaxHighlighter
      language={language}
      style={highlightStyle}
      customStyle={{ height: customHeight, minWidth: '550px', ...(maxHeight ? { maxHeight, overflowY: 'auto' } : {}) }}
      showLineNumbers={showLineNumbers}
      wrapLongLines={wrapLongLines}
      // The theme's code style sets white-space: pre after wrapLongLines sets pre-wrap: keep it, then wrap
      codeTagProps={wrapLongLines ? { style: { ...highlightStyle['code[class*="language-"]'], whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' } } : undefined}
    >
      {code}
    </SyntaxHighlighter>
  );
};

export default CodeBlock;
