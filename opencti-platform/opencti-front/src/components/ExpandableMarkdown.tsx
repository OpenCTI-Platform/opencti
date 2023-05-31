import React, { FunctionComponent, useState } from 'react';
import Markdown from 'react-markdown';
import { gfmFootnoteFromMarkdown, gfmFootnoteToMarkdown } from 'mdast-util-gfm-footnote';
import { gfmStrikethroughFromMarkdown, gfmStrikethroughToMarkdown } from 'mdast-util-gfm-strikethrough';
import { gfmTableFromMarkdown, gfmTableToMarkdown } from 'mdast-util-gfm-table';
import { gfmTaskListItemFromMarkdown, gfmTaskListItemToMarkdown } from 'mdast-util-gfm-task-list-item';
import remarkParse from 'remark-parse';
import { ExpandLess, ExpandMore } from '@mui/icons-material';
import IconButton from '@mui/material/IconButton';
import { useTheme } from '@mui/styles';
import { combineExtensions } from 'micromark-util-combine-extensions';
import { gfmFootnote } from 'micromark-extension-gfm-footnote';
import { gfmStrikethrough } from 'micromark-extension-gfm-strikethrough';
import { gfmTable } from 'micromark-extension-gfm-table';
import { gfmTaskListItem } from 'micromark-extension-gfm-task-list-item';
import { Theme } from './Theme';
import { truncate } from '../utils/String';

const gfmFromMarkdown = () => {
  return [
    gfmFootnoteFromMarkdown(),
    gfmStrikethroughFromMarkdown,
    gfmTableFromMarkdown,
    gfmTaskListItemFromMarkdown,
  ];
};

const gfmToMarkdown = (options: any) => {
  return {
    extensions: [
      gfmFootnoteToMarkdown(),
      gfmStrikethroughToMarkdown,
      gfmTableToMarkdown(options),
      gfmTaskListItemToMarkdown,
    ],
  };
};

export function remarkGfm(options = {}) {
  const data = this.data();

  /**
   * @param {string} field
   * @param {unknown} value
   */
  function add(field: string, value) {
    const list = /** @type {unknown[]} */ (
      // Other extensions
      /* c8 ignore next 2 */
      data[field] ? data[field] : (data[field] = [])
    );

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

interface ExpandableMarkdownProps {
  source: string | null,
  limit: number,
}

const ExpandableMarkdown: FunctionComponent<ExpandableMarkdownProps> = ({ source, limit }) => {
  const theme = useTheme<Theme>();
  const [expand, setExpand] = useState(false);

  const onClick = () => setExpand(!expand);
  const shouldBeTruncated = (source || '').length > limit;
  console.log('source', source);

  return (
    <span>
    {source
      ? <div style={{ position: 'relative' }}>
        {shouldBeTruncated && (
          <div style={{ position: 'absolute', top: -32, right: 0 }}>
            <IconButton onClick={onClick} size="large">
              {expand ? <ExpandLess/> : <ExpandMore/>}
            </IconButton>
          </div>
        )}
        <div style={{ marginTop: 10 }}>
          <Markdown
            remarkPlugins={[remarkGfm, remarkParse]}
            components={MarkDownComponents(theme)}
            className="markdown"
          >
            {expand ? source : truncate(source, limit)}
          </Markdown>
        </div>
        <div className="clearfix"/>
      </div>
      : ('-')
    }
    </span>
  );
};

export default ExpandableMarkdown;
