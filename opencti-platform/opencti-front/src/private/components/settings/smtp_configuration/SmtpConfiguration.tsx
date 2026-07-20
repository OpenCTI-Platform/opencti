import React, { FunctionComponent, Suspense, useState } from 'react';
import SmtpConfigurationForm from './SmtpConfigurationForm';
import SmtpTestDialog from './SmtpTestDialog';
import Breadcrumbs from 'src/components/Breadcrumbs';
import { useFormatter } from 'src/components/i18n';
import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableHead from '@mui/material/TableHead';
import TableRow from '@mui/material/TableRow';
import Alert from '@mui/material/Alert';
import { graphql, usePreloadedQuery } from 'react-relay';
import type { PreloadedQuery } from 'react-relay';
import { useQueryLoadingWithLoadQuery } from 'src/utils/hooks/useQueryLoading';
import Loader from 'src/components/Loader';
import { SmtpConfigurationQuery } from '@components/settings/smtp_configuration/__generated__/SmtpConfigurationQuery.graphql';
import ItemBoolean from 'src/components/ItemBoolean';
import Button from '@common/button/Button';
import Drawer from '@components/common/drawer/Drawer';
import Security from 'src/utils/Security';
import { SETTINGS_SETACCESSES } from 'src/utils/hooks/useGranted';
import Card from 'src/components/common/card/Card';

const smtpConfigurationQuery = graphql`
  query SmtpConfigurationQuery{
    smtpConfiguration{
        smtp_enabled
        use_db_config
        forced_sender_email
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
  const [testDialogOpen, setTestDialogOpen] = useState(false);

  const smtpEnabled = !!smtpConfiguration?.smtp_enabled;
  const authType = smtpConfiguration?.auth_type;
  const isForcedBySysAdmin = smtpConfiguration?.forced_sender_email === true;
  const useDbConfig = smtpConfiguration?.use_db_config === true;

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

  return (
    <div
      style={{
        margin: 0,
        padding: '0 200px 50px 0',
      }}
      data-testid="smtp-settings-page"
    >
      <Breadcrumbs elements={[{ label: t_i18n('Settings') }, { label: t_i18n('Security') }, { label: t_i18n('SMTP configuration'), current: true }]} />

      {isForcedBySysAdmin && (
        <Alert
          severity="warning"
          variant="outlined"
          style={{ marginTop: 20, padding: '0px 10px' }}
        >
          {t_i18n('Your platform administrator has disabled this feature. You cannot configure a new SMTP configuration within the interface.')}
        </Alert>
      )}

      {!isForcedBySysAdmin && !useDbConfig && smtpConfiguration && (
        <Alert
          severity="info"
          variant="outlined"
          style={{ marginTop: 20, padding: '0px 10px' }}
        >
          {t_i18n('Currently, the SMTP is configured via a backend configuration. To change your configuration, simply enable the usage of the Interface configuration & define your SMTP configuration in this screen.')}
        </Alert>
      )}

      <Security needs={[SETTINGS_SETACCESSES]}>
        {!isForcedBySysAdmin ? (
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 20 }}>
            {smtpConfiguration && useDbConfig && (
              <Button variant="secondary" onClick={() => setTestDialogOpen(true)}>
                {t_i18n('Test')}
              </Button>
            )}
            <Button onClick={() => setFormOpen(true)}>
              {t_i18n('Update')}
            </Button>
          </div>
        ) : <></>}
      </Security>

      <div style={isForcedBySysAdmin ? { opacity: 0.5, pointerEvents: 'none' } : undefined}>
        <Card title={t_i18n('SMTP configuration')} sx={{ marginTop: 2, paddingTop: 1 }}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell sx={{ fontWeight: 'bold', paddingY: 2 }}>{t_i18n('SMTP fields')}</TableCell>
                <TableCell sx={{ fontWeight: 'bold', paddingY: 2 }}>{t_i18n('SMTP value')}</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              <TableRow>
                <TableCell>{t_i18n('SMTP enabled')}</TableCell>
                <TableCell>
                  <ItemBoolean status={smtpEnabled} label={smtpEnabled ? t_i18n('Yes') : t_i18n('No')} />
                </TableCell>
              </TableRow>
              <TableRow>
                <TableCell>{t_i18n('Use configuration in interface')}</TableCell>
                <TableCell>{renderBoolean(smtpConfiguration?.use_db_config)}</TableCell>
              </TableRow>
              <TableRow>
                <TableCell>{t_i18n('Sender email address')}</TableCell>
                <TableCell>{renderText(smtpConfiguration?.sender_email_address)}</TableCell>
              </TableRow>
              <TableRow>
                <TableCell>{t_i18n('Hostname')}</TableCell>
                <TableCell>{renderText(smtpConfiguration?.hostname)}</TableCell>
              </TableRow>
              <TableRow>
                <TableCell>{t_i18n('Port')}</TableCell>
                <TableCell>{renderText(smtpConfiguration?.port)}</TableCell>
              </TableRow>
              <TableRow>
                <TableCell>{t_i18n('Use SSL/TLS')}</TableCell>
                <TableCell>{renderBoolean(smtpConfiguration?.use_ssl)}</TableCell>
              </TableRow>
              <TableRow>
                <TableCell>{t_i18n('Reject unauthorized certificates')}</TableCell>
                <TableCell>{renderBoolean(smtpConfiguration?.reject_unauthorized)}</TableCell>
              </TableRow>
              <TableRow>
                <TableCell>{t_i18n('Authentication type')}</TableCell>
                <TableCell>{renderText(authType)}</TableCell>
              </TableRow>
              {authType === 'basic' && (
                <>
                  <TableRow>
                    <TableCell>{t_i18n('Username')}</TableCell>
                    <TableCell>{renderText(smtpConfiguration?.username)}</TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell>{t_i18n('Password')}</TableCell>
                    <TableCell>
                      <ItemBoolean status={null} neutralLabel={smtpConfiguration ? '••••••••' : '-'} />
                    </TableCell>
                  </TableRow>
                </>
              )}
              {authType === 'oauth2' && (
                <>
                  <TableRow>
                    <TableCell>{t_i18n('OAuth user')}</TableCell>
                    <TableCell>{renderText(smtpConfiguration?.oauth_user)}</TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell>{t_i18n('OAuth client ID')}</TableCell>
                    <TableCell>
                      <ItemBoolean status={null} neutralLabel={smtpConfiguration ? '••••••••' : '-'} />
                    </TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell>{t_i18n('OAuth issuer')}</TableCell>
                    <TableCell>{renderText(smtpConfiguration?.oauth_issuer)}</TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell>{t_i18n('Refresh token expiration date')}</TableCell>
                    <TableCell>
                      {renderText(smtpConfiguration?.oauth_refresh_token_expires_at ? nsdt(smtpConfiguration.oauth_refresh_token_expires_at) : null)}
                    </TableCell>
                  </TableRow>
                </>
              )}
            </TableBody>
          </Table>
        </Card>
      </div>

      <Security needs={[SETTINGS_SETACCESSES]}>
        <>
          {!isForcedBySysAdmin && (
            <Drawer
              title={t_i18n('Update SMTP configuration')}
              open={formOpen}
              onClose={() => setFormOpen(false)}
            >
              <SmtpConfigurationForm
                smtpConfiguration={smtpConfiguration ?? null}
                onCompleted={handleFormCompleted}
                onCancel={() => setFormOpen(false)}
              />
            </Drawer>
          )}
          {!isForcedBySysAdmin && useDbConfig && (
            <SmtpTestDialog
              open={testDialogOpen}
              onClose={() => setTestDialogOpen(false)}
            />
          )}
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
