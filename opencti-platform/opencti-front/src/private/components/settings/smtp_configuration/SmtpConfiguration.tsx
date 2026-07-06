import React, { FunctionComponent, Suspense, useState } from 'react';
import SmtpConfigurationForm from './SmtpConfigurationForm';
import SmtpTestDialog from './SmtpTestDialog';
import Breadcrumbs from 'src/components/Breadcrumbs';
import { useFormatter } from 'src/components/i18n';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import { DialogActions } from '@mui/material';
import { MoreVertOutlined } from '@mui/icons-material';
import { graphql, usePreloadedQuery } from 'react-relay';
import { PreloadedQuery } from 'react-relay/relay-hooks/EntryPointTypes';
import { PopoverProps } from '@mui/material/Popover';
import { useQueryLoadingWithLoadQuery } from 'src/utils/hooks/useQueryLoading';
import Loader from 'src/components/Loader';
import { SmtpConfigurationQuery } from '@components/settings/smtp_configuration/__generated__/SmtpConfigurationQuery.graphql';
import ItemBoolean from 'src/components/ItemBoolean';
import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import Dialog from '@common/dialog/Dialog';
import Drawer from '@components/common/drawer/Drawer';
import useApiMutation from 'src/utils/hooks/useApiMutation';
import { MESSAGING$ } from 'src/relay/environment';
import Security from 'src/utils/Security';
import { SETTINGS_SETACCESSES } from 'src/utils/hooks/useGranted';

const smtpConfigurationDeleteMutation = graphql`
  mutation SmtpConfigurationDeleteMutation($id: ID!) {
    smtpConfigurationDelete(id: $id)
  }
`;

const smtpConfigurationQuery = graphql`
  query SmtpConfigurationQuery{
    smtpConfiguration{
        id
        smtp_enabled
        use_db_config
        sender_email_address
        hostname
        port
        use_ssl
        reject_unauthorized
        auth_type
        username
        oauth_user
        oauth_client_id
        oauth_issuer
        oauth_refresh_token_expires_at
    }
  }
`;

interface SmtpConfigurationComponentProps {
  smtpConfigurationQueryRef: PreloadedQuery<SmtpConfigurationQuery>;
  refetch: () => void;
}

const SmtpConfigurationComponent: FunctionComponent<SmtpConfigurationComponentProps> = ({
  smtpConfigurationQueryRef,
  refetch,
}) => {
  const { t_i18n, nsdt } = useFormatter();
  const { smtpConfiguration } = usePreloadedQuery(smtpConfigurationQuery, smtpConfigurationQueryRef);

  const [formOpen, setFormOpen] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [testDialogOpen, setTestDialogOpen] = useState(false);
  const [menuAnchorEl, setMenuAnchorEl] = useState<PopoverProps['anchorEl']>(null);
  const [commitDelete, isDeleting] = useApiMutation(smtpConfigurationDeleteMutation);

  const smtpEnabled = !!smtpConfiguration?.smtp_enabled;
  const authType = smtpConfiguration?.auth_type;

  const renderBoolean = (value: boolean | null | undefined) => (
    value === null || value === undefined
      ? <ItemBoolean status={null} neutralLabel="-" />
      : <ItemBoolean status={!!value} label={value ? t_i18n('Yes') : t_i18n('No')} />
  );

  const renderText = (value: string | number | null | undefined) => (
    <ItemBoolean status={null} neutralLabel={value !== null && value !== undefined && value !== '' ? String(value) : '-'} />
  );

  const handleFormCompleted = () => {
    setFormOpen(false);
    refetch();
  };

  const handleMenuOpen = (event: React.MouseEvent) => {
    setMenuAnchorEl(event.currentTarget);
  };

  const handleMenuClose = () => {
    setMenuAnchorEl(null);
  };

  const handleOpenDelete = () => {
    handleMenuClose();
    setDeleteDialogOpen(true);
  };

  const handleDelete = () => {
    if (!smtpConfiguration?.id) return;
    commitDelete({
      variables: { id: smtpConfiguration.id },
      onCompleted: () => {
        MESSAGING$.notifySuccess(t_i18n('SMTP configuration deleted'));
        setDeleteDialogOpen(false);
        refetch();
      },
    });
  };

  return (
    <div
      style={{
        margin: 0,
        padding: '0 200px 50px 0',
      }}
      data-testid="smtp-settings-page"
    >
      <Breadcrumbs elements={[{ label: t_i18n('Settings') }, { label: t_i18n('Security') }, { label: t_i18n('SMTP configuration'), current: true }]} />
      <Security needs={[SETTINGS_SETACCESSES]}>
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 20 }}>
          {smtpConfiguration && (
            <>
              <IconButton variant="secondary" size="default" onClick={handleMenuOpen}>
                <MoreVertOutlined fontSize="medium" />
              </IconButton>
              <Menu
                anchorEl={menuAnchorEl}
                open={!!menuAnchorEl}
                onClose={handleMenuClose}
              >
                <MenuItem onClick={handleOpenDelete}>
                  {t_i18n('Remove configuration')}
                </MenuItem>
              </Menu>
            </>
          )}
          {smtpConfiguration && (
            <Button variant="secondary" onClick={() => setTestDialogOpen(true)}>
              {t_i18n('Test')}
            </Button>
          )}
          <Button onClick={() => setFormOpen(true)}>
            {t_i18n('Update')}
          </Button>
        </div>
      </Security>
      <List style={{ marginTop: 20 }}>
        <ListItem divider={true}>
          <ListItemText primary={t_i18n('SMTP enabled')} />
          <ItemBoolean status={smtpEnabled} label={smtpEnabled ? t_i18n('Yes') : t_i18n('No')} />
        </ListItem>
        <ListItem divider={true}>
          <ListItemText primary={t_i18n('Use DB configuration')} />
          {renderBoolean(smtpConfiguration?.use_db_config)}
        </ListItem>
        <ListItem divider={true}>
          <ListItemText primary={t_i18n('Sender email address')} />
          {renderText(smtpConfiguration?.sender_email_address)}
        </ListItem>
        <ListItem divider={true}>
          <ListItemText primary={t_i18n('Hostname')} />
          {renderText(smtpConfiguration?.hostname)}
        </ListItem>
        <ListItem divider={true}>
          <ListItemText primary={t_i18n('Port')} />
          {renderText(smtpConfiguration?.port)}
        </ListItem>
        <ListItem divider={true}>
          <ListItemText primary={t_i18n('Use SSL/TLS')} />
          {renderBoolean(smtpConfiguration?.use_ssl)}
        </ListItem>
        <ListItem divider={true}>
          <ListItemText primary={t_i18n('Reject unauthorized certificates')} />
          {renderBoolean(smtpConfiguration?.reject_unauthorized)}
        </ListItem>
        <ListItem divider={true}>
          <ListItemText primary={t_i18n('Authentication type')} />
          {renderText(authType)}
        </ListItem>
        {authType === 'basic' && (
          <>
            <ListItem divider={true}>
              <ListItemText primary={t_i18n('Username')} />
              {renderText(smtpConfiguration?.username)}
            </ListItem>
            <ListItem divider={true}>
              <ListItemText primary={t_i18n('Password')} />
              <ItemBoolean status={null} neutralLabel={smtpConfiguration ? '••••••••' : '-'} />
            </ListItem>
          </>
        )}
        {authType === 'oauth2' && (
          <>
            <ListItem divider={true}>
              <ListItemText primary={t_i18n('OAuth user')} />
              {renderText(smtpConfiguration?.oauth_user)}
            </ListItem>
            <ListItem divider={true}>
              <ListItemText primary={t_i18n('OAuth client ID')} />
              <ItemBoolean status={null} neutralLabel={smtpConfiguration ? '••••••••' : '-'} />
            </ListItem>
            <ListItem divider={true}>
              <ListItemText primary={t_i18n('OAuth issuer')} />
              {renderText(smtpConfiguration?.oauth_issuer)}
            </ListItem>
            <ListItem divider={false}>
              <ListItemText primary={t_i18n('Refresh token expiration date')} />
              {renderText(smtpConfiguration?.oauth_refresh_token_expires_at ? nsdt(smtpConfiguration.oauth_refresh_token_expires_at) : null)}
            </ListItem>
          </>
        )}
      </List>
      <Security needs={[SETTINGS_SETACCESSES]}>
        <>
          <Drawer
            title={smtpConfiguration ? t_i18n('Update SMTP configuration') : t_i18n('Create SMTP configuration')}
            open={formOpen}
            onClose={() => setFormOpen(false)}
          >
            <SmtpConfigurationForm
              smtpConfiguration={smtpConfiguration ?? null}
              onCompleted={handleFormCompleted}
              onCancel={() => setFormOpen(false)}
            />
          </Drawer>
          <Dialog
            open={deleteDialogOpen}
            onClose={() => setDeleteDialogOpen(false)}
            title={t_i18n('Delete SMTP configuration')}
          >
            {t_i18n('Are you sure you want to delete this SMTP configuration?')}
            <DialogActions>
              <Button variant="secondary" onClick={() => setDeleteDialogOpen(false)}>
                {t_i18n('Cancel')}
              </Button>
              <Button color="error" disabled={isDeleting} onClick={handleDelete}>
                {t_i18n('Delete')}
              </Button>
            </DialogActions>
          </Dialog>
          <SmtpTestDialog
            open={testDialogOpen}
            onClose={() => setTestDialogOpen(false)}
          />
        </>
      </Security>
    </div>
  );
};

const SmtpConfiguration = () => {
  const [smtpConfigurationQueryRef, loadQuery] = useQueryLoadingWithLoadQuery<SmtpConfigurationQuery>(smtpConfigurationQuery);
  const refetch = () => loadQuery({}, { fetchPolicy: 'network-only' });

  return (
    <Suspense fallback={<Loader />}>
      {smtpConfigurationQueryRef && (
        <SmtpConfigurationComponent
          smtpConfigurationQueryRef={smtpConfigurationQueryRef}
          refetch={refetch}
        />
      )}
    </Suspense>
  );
};
export default SmtpConfiguration;
