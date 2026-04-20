import Markdown, { Options as MarkdownProps, defaultUrlTransform } from 'react-markdown';
import remarkParse from 'remark-parse';
import remarkFlexibleMarkers from 'remark-flexible-markers';
import { useTheme } from '@mui/styles';
import React, { FunctionComponent, SyntheticEvent, useCallback, useMemo, useState } from 'react';
import remarkGfm from 'remark-gfm';
import type { Theme } from './Theme';
import { truncate } from '../utils/String';
import ExternalLinkPopover from './ExternalLinkPopover';
import FieldOrEmpty from './FieldOrEmpty';
import { TEMP_IMAGE_SCHEME } from './fields/markdownField/markdownImageTempUtils';

const STORAGE_IMAGE_PATHS = ['/storage/view', '/storage/get'];
const markdownStyle: React.CSSProperties = {
  overflowWrap: 'break-word',
  wordBreak: 'break-word',
  hyphens: 'auto',
};

const isAllowedUploadedImageUrl = (url: string): boolean => {
  if (!url) return false;
  if (url.startsWith(TEMP_IMAGE_SCHEME)) return true;
  if (STORAGE_IMAGE_PATHS.some((path) => url.includes(path))) return true;
  return defaultUrlTransform(url) !== '';
};

const transformMarkdownUrl: NonNullable<MarkdownProps['urlTransform']> = (url) => {
  if (url.startsWith(TEMP_IMAGE_SCHEME)) {
    return url;
  }
  return defaultUrlTransform(url);
};

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
  content?: string | null;
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
  resolveImageUrl?: (url: string) => string | null;
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
  resolveImageUrl,
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
  const disallowedElements = useMemo(() => {
    const elements: string[] = [];
    if (removeLinks) {
      elements.push('a');
    }
    if (removeLineBreaks) {
      elements.push('p');
    }
    return elements;
  }, [removeLinks, removeLineBreaks]);

  const resolveMarkdownImageUrl = useCallback((url: string) => {
    return resolveImageUrl ? resolveImageUrl(url) : url;
  }, [resolveImageUrl]);

  const imageComponent = useMemo<MarkdownProps['components']>(() => ({
    img: ({ src, alt, ...imgProps }) => {
      const rawUrl = typeof src === 'string' ? src : '';
      const resolvedUrl = resolveMarkdownImageUrl(rawUrl);
      const isAllowedImage = isAllowedUploadedImageUrl(rawUrl)
        || (resolvedUrl ? isAllowedUploadedImageUrl(resolvedUrl) : false);
      if (!resolvedUrl || !isAllowedImage) {
        return <span>{alt || ''}</span>;
      }

      return (
        <img
          src={resolvedUrl}
          alt={alt || ''}
          style={{
            objectFit: 'cover',
            maxHeight: '200px',
          }}
          {...imgProps}
        />
      );
    },
  }), [resolveMarkdownImageUrl]);

  const markdownContent = useMemo(() => {
    return limit ? truncate(content, limit) : content;
  }, [content, limit]);

  const remarkContent = useMemo(() => {
    return expand || !limit ? content : truncate(content, limit);
  }, [content, expand, limit]);

  const markdownRender = useMemo(() => {
    if (!remarkGfmPlugin) {
      return (
        <div className="markdown" style={markdownStyle}>
          <Markdown
            components={imageComponent}
            urlTransform={transformMarkdownUrl}
            disallowedElements={disallowedElements}
            unwrapDisallowed={true}
          >
            {markdownContent}
          </Markdown>
        </div>
      );
    }

    if (remarkPlugins) {
      return (
        <div className="markdown" style={markdownStyle}>
          <Markdown
            remarkPlugins={remarkPlugins}
            components={imageComponent}
            urlTransform={transformMarkdownUrl}
            disallowedElements={disallowedElements}
            unwrapDisallowed={true}
          >
            {remarkContent}
          </Markdown>
        </div>
      );
    }

    if (markdownComponents) {
      return (
        <div className="markdown" style={markdownStyle}>
          <Markdown
            remarkPlugins={[
              remarkGfm,
              remarkFlexibleMarkers,
              [remarkParse, { commonmark: !!commonmark }],
            ]}
            components={{ ...MarkDownComponents(theme), ...imageComponent }}
            urlTransform={transformMarkdownUrl}
            disallowedElements={disallowedElements}
            unwrapDisallowed={true}
          >
            {remarkContent}
          </Markdown>
        </div>
      );
    }

    return (
      <div className="markdown" style={markdownStyle}>
        <Markdown
          remarkPlugins={[
            remarkGfm,
            remarkFlexibleMarkers,
            [remarkParse, { commonmark: !!commonmark }],
          ]}
          components={imageComponent}
          urlTransform={transformMarkdownUrl}
          disallowedElements={disallowedElements}
          unwrapDisallowed={true}
        >
          {markdownContent}
        </Markdown>
      </div>
    );
  }, [
    commonmark,
    disallowedElements,
    imageComponent,
    markdownComponents,
    markdownContent,
    remarkContent,
    remarkGfmPlugin,
    remarkPlugins,
    theme,
  ]);

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
    markdownDisplayContent = markdownRender;
  } else {
    markdownDisplayContent = (
      <>
        <div onClick={(event) => browseLinkWarning(event)}>
          {markdownRender}
        </div>
        <ExternalLinkPopover
          displayExternalLink={displayExternalLink}
          externalLink={externalLink}
          setDisplayExternalLink={setDisplayExternalLink}
          setExternalLink={setExternalLink}
        />
      </>
    );
  }
  return emptyStringIfUndefined ? markdownDisplayContent : <FieldOrEmpty source={content}>{markdownDisplayContent}</FieldOrEmpty>;
};

export default MarkdownDisplay;
