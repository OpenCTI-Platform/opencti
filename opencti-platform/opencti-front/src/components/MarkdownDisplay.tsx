import Markdown from 'react-markdown';
import remarkParse from 'remark-parse';
import remarkFlexibleMarkers from 'remark-flexible-markers';
import { useTheme } from '@mui/styles';
import { PluggableList } from 'react-markdown/lib/react-markdown';
import React, { FunctionComponent, SyntheticEvent, useState } from 'react';
import remarkGfm from 'remark-gfm';
import { Theme } from './Theme';
import { truncate } from '../utils/String';
import ExternalLinkPopover from './ExternalLinkPopover';
import FieldOrEmpty from './FieldOrEmpty';

export const MarkDownComponents = (
  theme: Theme,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
): Record<string, FunctionComponent<any>> => ({
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
  content: string;
  expand?: boolean;
  limit?: number;
  remarkGfmPlugin?: boolean;
  markdownComponents?: boolean;
  commonmark?: boolean;
  removeLinks?: boolean;
  remarkPlugins?: PluggableList;
}

const MarkdownDisplay: FunctionComponent<
MarkdownWithRedirectionWarningProps
> = ({
  content,
  expand,
  limit,
  remarkGfmPlugin,
  markdownComponents,
  commonmark,
  removeLinks,
  remarkPlugins,
}) => {
  const theme = useTheme<Theme>();
  const [displayExternalLink, setDisplayExternalLink] = useState(false);
  const [externalLink, setExternalLink] = useState<string | URL | undefined>(
    undefined,
  );
  const handleOpenExternalLink = (url: string) => {
    setDisplayExternalLink(true);
    setExternalLink(url);
  };
  const markdownElement = () => {
    return (
      <Markdown
        className="markdown"
        disallowedElements={removeLinks ? ['a'] : []}
        unwrapDisallowed={true}
      >
        {limit ? truncate(content, limit) : content}
      </Markdown>
    );
  };
  const remarkGfmMarkdownElement = () => {
    if (remarkPlugins) {
      return (
        <Markdown
          className="markdown"
          remarkPlugins={remarkPlugins}
          disallowedElements={removeLinks ? ['a'] : []}
          unwrapDisallowed={true}
        >
          {expand || !limit ? content : truncate(content, limit)}
        </Markdown>
      );
    }
    if (markdownComponents) {
      return (
        <Markdown
          className="markdown"
          remarkPlugins={
            [
              remarkGfm,
              remarkFlexibleMarkers,
              [remarkParse, { commonmark: !!commonmark }],
            ] as PluggableList
          }
          components={MarkDownComponents(theme)}
          disallowedElements={removeLinks ? ['a'] : []}
          unwrapDisallowed={true}
        >
          {expand || !limit ? content : truncate(content, limit)}
        </Markdown>
      );
    }
    return (
      <Markdown
        className="markdown"
        remarkPlugins={
          [
            remarkGfm,
            remarkFlexibleMarkers,
            [remarkParse, { commonmark: !!commonmark }],
          ] as PluggableList
        }
        disallowedElements={removeLinks ? ['a'] : []}
        unwrapDisallowed={true}
      >
        {limit ? truncate(content, limit) : content}
      </Markdown>
    );
  };
  const browseLinkWarning = (
    event: SyntheticEvent<HTMLElement, MouseEvent>,
  ) => {
    if ((event.target as HTMLElement).localName === 'a') {
      // if the user clicks on a link
      event.stopPropagation();
      event.preventDefault();
      const link = event.target as HTMLLinkElement;
      handleOpenExternalLink(link.href);
    }
  };
  if (removeLinks) {
    return (
      <FieldOrEmpty source={content}>
        {remarkGfmPlugin ? remarkGfmMarkdownElement() : markdownElement()}
      </FieldOrEmpty>
    );
  }
  return (
    <FieldOrEmpty source={content}>
      <div onClick={(event) => browseLinkWarning(event)}>
        {remarkGfmPlugin ? remarkGfmMarkdownElement() : markdownElement()}
      </div>
      <ExternalLinkPopover
        displayExternalLink={displayExternalLink}
        externalLink={externalLink}
        setDisplayExternalLink={setDisplayExternalLink}
        setExternalLink={setExternalLink}
      />
    </FieldOrEmpty>
  );
};

export default MarkdownDisplay;
