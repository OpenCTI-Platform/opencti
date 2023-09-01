import React, { FunctionComponent } from 'react';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { a11yDark } from 'react-syntax-highlighter/dist/esm/styles/prism';

interface CodeBlockProps {
  code: string;
  language: string;
}

const CodeBlock: FunctionComponent<CodeBlockProps> = ({ language, code }) => {
  return (
    <SyntaxHighlighter language={language}
                       style={a11yDark}
                       customStyle={{ height: '400px', minWidth: '550px' }}
                       showLineNumbers
    >
      {code}
    </SyntaxHighlighter>
  );
};

export default CodeBlock;
