import React, { FunctionComponent, useMemo, useState } from 'react';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import { DialogTitle } from '@mui/material';
import DialogContent from '@mui/material/DialogContent';
import { graphql, useSubscription } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import { CKEditor } from '@ckeditor/ckeditor5-react';
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import Editor from 'ckeditor5-custom-build/build/ckeditor';
import 'ckeditor5-custom-build/build/translations/fr';
import 'ckeditor5-custom-build/build/translations/zh-cn';
import { ResponseDialogAskAISubscription, ResponseDialogAskAISubscription$data } from './__generated__/ResponseDialogAskAISubscription.graphql';
import { useFormatter } from '../../components/i18n';

// region types
interface ResponseDialogProps {
  id: string;
  isOpen: boolean;
  isDisabled: boolean;
  handleClose: () => void;
  handleAccept: () => void;
  handleFollowUp: () => void;
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

const ResponseDialog: FunctionComponent<ResponseDialogProps> = ({ id, isOpen, isDisabled, handleClose, handleAccept, handleFollowUp, followUpActions }) => {
  const { t_i18n } = useFormatter();
  const [content, setContent] = useState('');
  const handleResponse = (response: ResponseDialogAskAISubscription$data | null | undefined | unknown) => {
    const newContent = response ? (response as ResponseDialogAskAISubscription$data).aiBus?.content : null;
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
  return (
    <>
      <Dialog
        PaperProps={{ elevation: 1 }}
        open={isOpen}
        onClose={handleClose}
        fullWidth={true}
      >
        <DialogTitle>{t_i18n('Ask AI')}</DialogTitle>
        <DialogContent>
          <div style={{ width: '100%', minHeight: 500, height: 500 }}>
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
            />
          </div>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleClose}>
            {t_i18n('Close')}
          </Button>
          <Button color="secondary">
            {t_i18n('Continue')}
          </Button>
          <Button onClick={handleAccept} color="secondary">
            {t_i18n('Accept')}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
};

export default ResponseDialog;
