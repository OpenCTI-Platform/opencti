import Markdown from 'react-markdown';
import { gfmFootnoteFromMarkdown, gfmFootnoteToMarkdown } from 'mdast-util-gfm-footnote';
import { gfmStrikethroughFromMarkdown, gfmStrikethroughToMarkdown } from 'mdast-util-gfm-strikethrough';
import { gfmTableFromMarkdown, gfmTableToMarkdown } from 'mdast-util-gfm-table';
import { gfmTaskListItemFromMarkdown, gfmTaskListItemToMarkdown } from 'mdast-util-gfm-task-list-item';
import remarkParse from 'remark-parse';
import { useTheme } from '@mui/styles';
import { combineExtensions } from 'micromark-util-combine-extensions';
import { gfmFootnote } from 'micromark-extension-gfm-footnote';
import { gfmStrikethrough } from 'micromark-extension-gfm-strikethrough';
import { gfmTable } from 'micromark-extension-gfm-table';
import { gfmTaskListItem } from 'micromark-extension-gfm-task-list-item';
import { Options as TableOptions } from 'mdast-util-gfm-table/lib';
import { Options as ToMarkdownOptions } from 'mdast-util-to-markdown/lib';
import { Extension } from 'micromark-extension-gfm';
import Config from 'remark-parse/lib';
import { PluggableList } from 'react-markdown/lib/react-markdown';
import { FrozenProcessor } from 'unified';
import React, { FunctionComponent, SyntheticEvent, useState } from 'react';
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

const gfmFromMarkdown = () => {
  return [
    gfmFootnoteFromMarkdown(),
    gfmStrikethroughFromMarkdown,
    gfmTableFromMarkdown,
    gfmTaskListItemFromMarkdown,
  ];
};

const gfmToMarkdown = (options?: TableOptions | null | undefined) => {
  return {
    extensions: [
      gfmFootnoteToMarkdown(),
      gfmStrikethroughToMarkdown,
      gfmTableToMarkdown(options),
      gfmTaskListItemToMarkdown,
    ],
  };
};

export function remarkGfm(this: FrozenProcessor, options = {}) {
  const data = this.data();

  function add(field: string, value: Extension | Partial<typeof Config>[] | { extensions: ToMarkdownOptions[] }) {
    const list = (
      data[field] ? data[field] : (data[field] = [])
    ) as (Extension | Partial<typeof Config>[] | { extensions: ToMarkdownOptions[] })[];

    list.push(value);
  }
  const micromarkExtensions = combineExtensions([
    gfmFootnote(),
    gfmStrikethrough(options),
    gfmTable,
    gfmTaskListItem,
  ]);

  add('micromarkExtensions', micromarkExtensions);
  add('fromMarkdownExtensions', gfmFromMarkdown());
  add('toMarkdownExtensions', gfmToMarkdown(options));
}

interface RemarkGfmMarkdownProps {
  content: string,
  expand?: boolean,
  limit?: number,
  markdownComponents?: boolean,
  commonmark?: boolean,
}

const RemarkGfmMarkdown: FunctionComponent<RemarkGfmMarkdownProps> = ({ content, expand, limit, markdownComponents, commonmark }) => {
  const theme = useTheme<Theme>();
  const [displayExternalLink, setDisplayExternalLink] = useState(false);
  const [externalLink, setExternalLink] = useState<string | URL | undefined>(undefined);

  const handleOpenExternalLink = (url: string) => {
    setDisplayExternalLink(true);
    setExternalLink(url);
  };

  const markdownElement = () => {
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
        {markdownElement()}
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

export default RemarkGfmMarkdown;
