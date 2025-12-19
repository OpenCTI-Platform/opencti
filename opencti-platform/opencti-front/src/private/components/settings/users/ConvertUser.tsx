import React, { FunctionComponent, useState } from 'react';
import Dialog from '@mui/material/Dialog';
import Alert from '@mui/material/Alert';
import { DialogTitle } from '@mui/material';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Button from '@common/button/Button';
import { graphql } from 'react-relay';
import DialogContentText from '@mui/material/DialogContentText';
import { useTheme } from '@mui/styles';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import Transition from '../../../../components/Transition';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';

const convertUserMutation = graphql`
  mutation ConvertUserMutation(
    $id: ID!
    $input: [EditInput]!
  ) {
    userEdit(id: $id) {
      fieldPatch(input: $input) {
        id
        user_service_account
      }
    }
  }
`;

interface ConvertUserProps {
  userId: string;
  userServiceAccount: boolean;
}

const ConvertUser: FunctionComponent<ConvertUserProps> = ({ userId, userServiceAccount }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const [openDialog, setOpenDialog] = useState(false);
  const handleClose = () => {
    setOpenDialog(false);
  };
  const [commit] = useApiMutation(convertUserMutation);
  const onSubmit = () => {
    commit({
      variables: {
        id: userId,
        input: [{ key: 'user_service_account', value: [!userServiceAccount] }],
      },
      onCompleted: () => {
        handleClose?.();
        setOpenDialog(false);
      },
      onError: () => {
      },
    });
  };

  const getAlertText = () => {
    if (userServiceAccount) {
      return (
        <div>
          <div>{t_i18n('You are about to convert this service account into a user. This means that:')}</div>
          <ul>
            <li>{t_i18n('a random password will be generated for your user: you will need to change it to be able to log in via email and password. Simply use the forget password workflow.')}</li>
            <li>{t_i18n('if your service account has been created originally as a service account (not transformed), please also change the email of your service account before/after transforming it to a user to ensure that the future user will be able to receive an email in the forgot password workflow.')}</li>
            <li>{t_i18n('you will not pertain to the main platform organisation anymore unless you have been specifically granted access to the organisation.')}</li>
          </ul>
        </div>
      );
    }
    return (
      <div>
        <div>{t_i18n('You are about to convert this user into a service account. This means that:')}</div>
        <ul>
          <li>{t_i18n('password will be cleaned: you will not be able to log in to ui with this service account given there will be no password in Database for this service account.')}</li>
          <li>{t_i18n('your user will pertain to the main platform organisation in addition to any organisation that the current user is belonging to')}</li>
          <li>{t_i18n('your service account won\'t be able to receive notifications')}</li>
          <li> {t_i18n('You will be able to revert this change if needed. ')}</li>
        </ul>
      </div>
    );
  };

  return (
    <div>
      <Button
        variant="secondary"
        onClick={() => setOpenDialog(true)}
        value="convert-user"
      >
        {t_i18n('Convert')}
      </Button>
      <Dialog
        open={openDialog}
        slotProps={{ paper: { elevation: 1 } }}
        keepMounted={true}
        slots={{ transition: Transition }}
        maxWidth="sm"
        fullWidth={true}
        onClose={() => {
          handleClose();
        }}
      >
        <DialogTitle>{userServiceAccount ? t_i18n('Convert Service account into User') : t_i18n('Convert User into Service account')}</DialogTitle>
        <DialogContent>
          <DialogContentText>
            <Alert
              severity="warning"
              variant="outlined"
              color="dangerZone"
              style={{
                borderColor: theme.palette.dangerZone.main,
              }}
            >
              {getAlertText()}
            </Alert>
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button
            variant="secondary"
            onClick={() => {
              handleClose();
            }}
          >
            {t_i18n('Cancel')}
          </Button>
          <Button
            onClick={onSubmit}
          >
            {t_i18n('Convert')}
          </Button>
        </DialogActions>
      </Dialog>
    </div>
  );
};

export default ConvertUser;
