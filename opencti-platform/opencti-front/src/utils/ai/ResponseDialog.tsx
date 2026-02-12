import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import Alert from '@mui/material/Alert';
import DialogActions from '@mui/material/DialogActions';
import TextField from '@mui/material/TextField';
import { FunctionComponent, useMemo, useRef, useState } from 'react';
import ReactMde from 'react-mde';
import { graphql, useSubscription } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
// As we can ask AI after and follow up, there is a dependency lifecycle here that can be accepted
// TODO: Cleanup a bit in upcoming version

import CKEditor from '../../components/CKEditor';
import { useFormatter } from '../../components/i18n';
import MarkdownDisplay from '../../components/MarkdownDisplay';
import TextFieldAskAI from '../../private/components/common/form/TextFieldAskAI';
import useAI from '../hooks/useAI';
import { isNotEmptyField } from '../utils';
import { ResponseDialogAskAISubscription, ResponseDialogAskAISubscription$data } from './__generated__/ResponseDialogAskAISubscription.graphql';

// region types
interface ResponseDialogProps {
  id: string;
  isOpen: boolean;
  isDisabled: boolean;
  handleClose: () => void;
  handleAccept: (content: string) => void;
  handleFollowUp: () => void;
  content: string;
  setContent: (content: string) => void;
  format: 'text' | 'html' | 'markdown' | 'json';
  isAcceptable?: boolean;
  followUpActions: {
    key: string;
    label: string;
  }[];
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
  content,
  setContent,
}) => {
  const textFieldRef = useRef<HTMLTextAreaElement>(null);
  const markdownFieldRef = useRef<HTMLTextAreaElement>(null);
  const { t_i18n } = useFormatter();
  const [markdownSelectedTab, setMarkdownSelectedTab] = useState<'write' | 'preview' | undefined>('write');
  const { fullyActive } = useAI();

  const handleResponse = (response: ResponseDialogAskAISubscription$data | null | undefined) => {
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
    GraphQLSubscriptionConfig<ResponseDialogAskAISubscription>>(
    () => ({
      subscription,
      variables: { id },
      onNext: handleResponse,
    }),
    [id],
  );
  // TODO: Check by the engineering team
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  useSubscription(subConfig);
  const height = 400;
  return (
    <>
      <Dialog
        open={isOpen}
        onClose={() => {
          setContent('');
          handleClose();
        }}
        title={t_i18n('Ask AI')}
      >
        <div style={{ width: '100%', minHeight: height, height, position: 'relative' }}>
          {(format === 'text' || format === 'json') && (
            <TextField
              inputRef={textFieldRef}
              disabled={isDisabled}
              rows={Math.round(height / 23)}
              value={content}
              multiline={true}
              onChange={(event) => setContent(event.target.value)}
              fullWidth={true}
              slotProps={{
                input: {
                  endAdornment: fullyActive && (
                    <TextFieldAskAI
                      currentValue={content ?? ''}
                      setFieldValue={(val) => {
                        setContent(val);
                      }}
                      format="text"
                      variant="text"
                      disabled={isDisabled}
                    />
                  ),
                },
              }}
            />
          )}
          {format === 'html' && (
            <CKEditor
              id="response-dialog-editor"
              data={content}
              onChange={(_, editor) => {
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
          {(format === 'markdown' || format === 'html') && (
            <TextFieldAskAI
              currentValue={content ?? ''}
              setFieldValue={(val) => {
                setContent(val);
              }}
              format={format}
              variant={format}
              disabled={isDisabled}
              style={format === 'html' ? { position: 'absolute', top: 2, right: 45 } : undefined}
            />
          )}
        </div>
        <div className="clearfix" />
        <Alert severity="warning" variant="outlined" style={format === 'html' ? { marginTop: 30 } : {}}>
          {t_i18n('Generative AI is a beta feature as we are currently fine-tuning our models. Consider checking important information.')}
        </Alert>

        <DialogActions>
          <Button variant="secondary" onClick={handleClose}>
            {t_i18n('Close')}
          </Button>
          {isAcceptable && (
            <Button
              disabled={isDisabled}
              onClick={() => handleAccept(content)}
            >
              {t_i18n('Accept')}
            </Button>
          )}
        </DialogActions>
      </Dialog>
    </>
  );
};

export default ResponseDialog;
