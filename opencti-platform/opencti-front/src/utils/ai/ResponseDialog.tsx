import React, { FunctionComponent, useMemo, useState, useRef } from 'react';
import DialogActions from '@mui/material/DialogActions';
import LoadingButton from '@mui/lab/LoadingButton';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import Alert from '@mui/material/Alert';
import { graphql, useSubscription } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import { CKEditor } from '@ckeditor/ckeditor5-react';
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import Editor from 'ckeditor5-custom-build/build/ckeditor';
import 'ckeditor5-custom-build/build/translations/fr';
import 'ckeditor5-custom-build/build/translations/zh-cn';
import ReactMde from 'react-mde';
import TextField from '@mui/material/TextField';
import { ResponseDialogAskAISubscription, ResponseDialogAskAISubscription$data } from './__generated__/ResponseDialogAskAISubscription.graphql';
import { useFormatter } from '../../components/i18n';
import MarkdownDisplay from '../../components/MarkdownDisplay';
import { isNotEmptyField } from '../utils';

// region types
interface ResponseDialogProps {
  id: string;
  isOpen: boolean;
  isDisabled: boolean;
  handleClose: () => void;
  handleAccept: (content: string) => void;
  handleFollowUp: () => void;
  format: 'text' | 'html' | 'markdown' | 'json';
  isAcceptable?: boolean;
  followUpActions: {
    key: string;
    label: string;
  }[]
}

const subscription = graphql`
    subscription ResponseDialogAskAISubscription($id: ID!) {
        aiBus(id: $id) {
          content
        }
    }
`;

const ResponseDialog: FunctionComponent<ResponseDialogProps> = ({
  id,
  isOpen,
  isDisabled,
  handleClose,
  handleAccept,
  format,
  isAcceptable = true,
}) => {
  const textFieldRef = useRef<HTMLTextAreaElement>(null);
  const markdownFieldRef = useRef<HTMLTextAreaElement>(null);
  const { t_i18n } = useFormatter();
  const [content, setContent] = useState('');
  const [markdownSelectedTab, setMarkdownSelectedTab] = useState<'write' | 'preview' | undefined>('write');
  const handleResponse = (response: ResponseDialogAskAISubscription$data | null | undefined | unknown) => {
    const newContent = response ? (response as ResponseDialogAskAISubscription$data).aiBus?.content : null;
    if (format === 'text' || format === 'json') {
      if (isNotEmptyField(textFieldRef?.current?.scrollTop)) {
        textFieldRef.current.scrollTop = textFieldRef.current.scrollHeight;
      }
    } else if (format === 'markdown') {
      if (isNotEmptyField(markdownFieldRef?.current?.scrollTop)) {
        markdownFieldRef.current.scrollTop = markdownFieldRef.current.scrollHeight;
      }
    } else if (format === 'html') {
      const elementCkEditor = document.querySelector(
        '.ck-content.ck-editor__editable.ck-editor__editable_inline',
      );
      elementCkEditor?.lastElementChild?.scrollIntoView();
    }
    return setContent(newContent ?? '');
  };
  const subConfig = useMemo<
  GraphQLSubscriptionConfig<ResponseDialogAskAISubscription>
  >(
    () => ({
      subscription,
      variables: { id },
      onNext: handleResponse,
    }),
    [id],
  );
  useSubscription(subConfig);
  const height = 500;
  return (
    <>
      <Dialog
        PaperProps={{ elevation: 1 }}
        open={isOpen}
        onClose={() => {
          setContent('');
          handleClose();
        }}
        fullWidth={true}
        maxWidth="lg"
      >
        <DialogTitle>{t_i18n('Ask AI')}</DialogTitle>
        <DialogContent>
          <div style={{ width: '100%', minHeight: height, height }}>
            {(format === 'text' || format === 'json') && (
              <TextField
                inputRef={textFieldRef}
                disabled={isDisabled}
                rows={Math.round(height / 23)}
                value={content}
                multiline={true}
                onChange={(event) => setContent(event.target.value)}
                fullWidth={true}
              />
            )}
            {format === 'html' && (
              <CKEditor
                editor={Editor}
                config={{ language: 'en' }}
                data={content}
                onChange={(_, editor) => {
                  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
                  // @ts-ignore
                  setContent(editor.getData());
                }}
                disabled={isDisabled}
                disableWatchdog={true}
              />
            )}
            {format === 'markdown' && (
            <ReactMde
              childProps={{
                textArea: {
                  ref: markdownFieldRef,
                },
              }}
              readOnly={isDisabled}
              value={content}
              minEditorHeight={height - 80}
              maxEditorHeight={height - 80}
              onChange={setContent}
              selectedTab={markdownSelectedTab}
              onTabChange={setMarkdownSelectedTab}
              generateMarkdownPreview={(markdown) => Promise.resolve(
                <MarkdownDisplay
                  content={markdown}
                  remarkGfmPlugin={true}
                  commonmark={true}
                />,
              )}
              l18n={{
                write: t_i18n('Write'),
                preview: t_i18n('Preview'),
                uploadingImage: t_i18n('Uploading image'),
                pasteDropSelect: t_i18n('Paste'),
              }}
            />
            )}
          </div>
          <Alert severity="warning" variant="outlined">
            {t_i18n('Generative AI is a beta feature as we are currently fine-tuning our models. Consider checking important information.')}
          </Alert>
        </DialogContent>
        <DialogActions>
          <LoadingButton onClick={handleClose} disabled={isDisabled}>
            {t_i18n('Close')}
          </LoadingButton>
          <LoadingButton color="secondary" disabled={true}>
            {t_i18n('Continue')}
          </LoadingButton>
          {isAcceptable && (
            <LoadingButton loading={isDisabled} color="secondary" onClick={() => handleAccept(content)}>
              {t_i18n('Accept')}
            </LoadingButton>
          )}
        </DialogActions>
      </Dialog>
    </>
  );
};

export default ResponseDialog;
