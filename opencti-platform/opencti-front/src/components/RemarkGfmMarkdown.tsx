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
import React, { FunctionComponent, useState } from 'react';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import Slide, { SlideProps } from '@mui/material/Slide';
import { Theme } from './Theme';
import { truncate } from '../utils/String';
import { useFormatter } from './i18n';

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

const Transition = React.forwardRef((props: SlideProps, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

interface RemarkGfmMarkdownProps {
  content: string,
  expand?: boolean,
  limit?: number,
  markdownComponents?: boolean,
  commonmark?: boolean,
}

const RemarkGfmMarkdown: FunctionComponent<RemarkGfmMarkdownProps> = ({ content, expand, limit, markdownComponents, commonmark }) => {
  const theme = useTheme<Theme>();
  const { t } = useFormatter();

  const [displayExternalLink, setDisplayExternalLink] = useState(false);
  const [externalLink, setExternalLink] = useState<string | URL | undefined>(undefined);

  const handleOpenExternalLink = (url: string) => {
    setDisplayExternalLink(true);
    setExternalLink(url);
  };

  const handleCloseExternalLink = () => {
    setDisplayExternalLink(false);
    setExternalLink(undefined);
  };

  const handleBrowseExternalLink = () => {
    window.open(externalLink, '_blank');
    setDisplayExternalLink(false);
    setExternalLink(undefined);
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

  const browseLinkWarning = (event: React.MouseEvent<HTMLDivElement, MouseEvent>) => {
    event.stopPropagation();
    event.preventDefault();
    if (event.target.localName === 'a') { // if the user clicks on a link
      if (event.target.outerHTML.startsWith('<a href="url">')) { // case: link contains in the text
        handleOpenExternalLink(event.target.innerText);
      } else { // case: link contains in a specified url
        handleOpenExternalLink(event.target.href);
      }
    }
  };

  return (
    <div>
      <div onClick={(event) => browseLinkWarning(event)}>
        {markdownElement()}
      </div>
      <Dialog
        PaperProps={{ elevation: 1 }}
        open={displayExternalLink}
        keepMounted={true}
        TransitionComponent={Transition}
        onClose={handleCloseExternalLink}
      >
        <DialogContent>
          <DialogContentText>
            {t('Do you want to browse this external link?')}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseExternalLink}>{t('Cancel')}</Button>
          <Button color="secondary" onClick={handleBrowseExternalLink}>
            {t('Browse the link')}
          </Button>
        </DialogActions>
      </Dialog>
    </div>
  );
};

export default RemarkGfmMarkdown;
