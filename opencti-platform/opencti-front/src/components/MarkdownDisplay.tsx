import Markdown, { Options as MarkdownProps } from 'react-markdown';
import remarkParse from 'remark-parse';
import remarkFlexibleMarkers from 'remark-flexible-markers';
import { useTheme } from '@mui/styles';
import React, { FunctionComponent, SyntheticEvent, useState } from 'react';
import remarkGfm from 'remark-gfm';
import type { Theme } from './Theme';
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
  content: string | null;
  expand?: boolean;
  limit?: number;
  remarkGfmPlugin?: boolean;
  markdownComponents?: boolean;
  commonmark?: boolean;
  removeLinks?: boolean;
  removeLineBreaks?: boolean;
  remarkPlugins?: MarkdownProps['remarkPlugins'];
  emptyStringIfUndefined?: boolean;
  disableWarningAtLinkClick?: boolean;
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
  removeLineBreaks,
  remarkPlugins,
  emptyStringIfUndefined,
  disableWarningAtLinkClick,
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
  const disallowedElements: string[] = [];
  if (removeLinks) {
    disallowedElements.push('a');
  }
  if (removeLineBreaks) {
    disallowedElements.push('p');
  }
  const markdownElement = () => {
    return (
      <div className="markdown">
        <Markdown
          disallowedElements={disallowedElements}
          unwrapDisallowed={true}
        >
          {limit ? truncate(content, limit) : content}
        </Markdown>
      </div>
    );
  };
  const remarkGfmMarkdownElement = () => {
    if (remarkPlugins) {
      return (
        <div className="markdown">
          <Markdown
            remarkPlugins={remarkPlugins}
            disallowedElements={disallowedElements}
            unwrapDisallowed={true}
          >
            {expand || !limit ? content : truncate(content, limit)}
          </Markdown>
        </div>

      );
    }
    if (markdownComponents) {
      return (
        <div className="markdown">
          <Markdown
            remarkPlugins={[
              remarkGfm,
              remarkFlexibleMarkers,
              [remarkParse, { commonmark: !!commonmark }],
            ]}
            components={MarkDownComponents(theme)}
            disallowedElements={disallowedElements}
            unwrapDisallowed={true}
          >
            {expand || !limit ? content : truncate(content, limit)}
          </Markdown>
        </div>
      );
    }
    return (
      <div className="markdown">
        <Markdown
          remarkPlugins={[
            remarkGfm,
            remarkFlexibleMarkers,
            [remarkParse, { commonmark: !!commonmark }],
          ]}
          disallowedElements={disallowedElements}
          unwrapDisallowed={true}
        >
          {limit ? truncate(content, limit) : content}
        </Markdown>
      </div>
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
  let markdownDisplayContent;
  if (disableWarningAtLinkClick || removeLinks || removeLineBreaks) {
    markdownDisplayContent = remarkGfmPlugin ? remarkGfmMarkdownElement() : markdownElement();
  } else {
    markdownDisplayContent = <>
      <div onClick={(event) => browseLinkWarning(event)}>
        {remarkGfmPlugin ? remarkGfmMarkdownElement() : markdownElement()}
      </div>
      <ExternalLinkPopover
        displayExternalLink={displayExternalLink}
        externalLink={externalLink}
        setDisplayExternalLink={setDisplayExternalLink}
        setExternalLink={setExternalLink}
      />
    </>;
  }
  return emptyStringIfUndefined ? markdownDisplayContent : <FieldOrEmpty source={content}>{markdownDisplayContent}</FieldOrEmpty>;
};

export default MarkdownDisplay;
