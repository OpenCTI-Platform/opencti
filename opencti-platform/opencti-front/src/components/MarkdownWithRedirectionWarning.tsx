import Markdown from 'react-markdown';
import remarkParse from 'remark-parse';
import { useTheme } from '@mui/styles';
import { PluggableList } from 'react-markdown/lib/react-markdown';
import React, { FunctionComponent, SyntheticEvent, useState } from 'react';
import remarkGfm from 'remark-gfm';
import { Theme } from './Theme';
import { truncate } from '../utils/String';
import ExternalLinkPopover from './ExternalLinkPopover';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const MarkDownComponents = (theme: Theme): Record<string, FunctionComponent<any>> => ({
  table: ({ tableProps }) => (
    <table
      style={{
        border: `1px solid ${theme.palette.divider}`,
        borderCollapse: 'collapse',
      }}
      {...tableProps}
    />
  ),
  tr: ({ trProps }) => (
    <tr style={{ border: `1px solid ${theme.palette.divider}` }} {...trProps} />
  ),
  td: ({ tdProps }) => (
    <td
      style={{
        border: `1px solid ${theme.palette.divider}`,
        padding: 5,
      }}
      {...tdProps}
    />
  ),
  th: ({ tdProps }) => (
    <th
      style={{
        border: `1px solid ${theme.palette.divider}`,
        padding: 5,
      }}
      {...tdProps}
    />
  ),
});

interface MarkdownWithRedirectionWarningProps {
  content: string,
  expand?: boolean,
  limit?: number,
  remarkGfmPlugin?: boolean
  markdownComponents?: boolean,
  commonmark?: boolean,
  remarkPlugins?: PluggableList,
}

const MarkdownWithRedirectionWarning: FunctionComponent<MarkdownWithRedirectionWarningProps> = ({
  content,
  expand,
  limit,
  remarkGfmPlugin,
  markdownComponents,
  commonmark,
  remarkPlugins,
}) => {
  const theme = useTheme<Theme>();
  const [displayExternalLink, setDisplayExternalLink] = useState(false);
  const [externalLink, setExternalLink] = useState<string | URL | undefined>(undefined);

  const handleOpenExternalLink = (url: string) => {
    setDisplayExternalLink(true);
    setExternalLink(url);
  };

  const markdownElement = () => {
    return (
      <Markdown>
        {limit ? truncate(content, limit) : content}
      </Markdown>
    );
  };

  const remarkGfmMarkdownElement = () => {
    if (remarkPlugins) {
      return (
        <Markdown
          remarkPlugins={remarkPlugins}
          className="markdown"
        >
          {(expand || !limit) ? content : truncate(content, limit)}
        </Markdown>
      );
    }
    if (markdownComponents) {
      return (
        <Markdown
          remarkPlugins={[remarkGfm, [remarkParse, { commonmark: (!!commonmark) }]] as PluggableList}
          components={MarkDownComponents(theme)}
          className="markdown"
        >
          {(expand || !limit) ? content : truncate(content, limit)}
        </Markdown>
      );
    }
    return (
      <Markdown
        remarkPlugins={[remarkGfm, [remarkParse, { commonmark: (!!commonmark) }]] as PluggableList}
        className="markdown"
      >
        {limit ? truncate(content, limit) : content}
      </Markdown>
    );
  };

  const browseLinkWarning = (event: SyntheticEvent<HTMLElement, MouseEvent>) => {
    event.stopPropagation();
    event.preventDefault();
    if ((event.target as HTMLElement).localName === 'a') { // if the user clicks on a link
      const link = event.target as HTMLLinkElement;
      handleOpenExternalLink(link.href);
    }
  };

  return (
    <div>
      <div onClick={(event) => browseLinkWarning(event)}>
        {remarkGfmPlugin ? remarkGfmMarkdownElement() : markdownElement()}
      </div>
      <ExternalLinkPopover
        displayExternalLink={displayExternalLink}
        externalLink={externalLink}
        setDisplayExternalLink={setDisplayExternalLink}
        setExternalLink={setExternalLink}
      ></ExternalLinkPopover>
    </div>
  );
};

export default MarkdownWithRedirectionWarning;
