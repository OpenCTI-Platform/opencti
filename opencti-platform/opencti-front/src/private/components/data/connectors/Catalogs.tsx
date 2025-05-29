import React, { useState } from 'react';
import Typography from '@mui/material/Typography';
import Alert from '@mui/material/Alert';
import { Add, HubOutlined, InfoOutlined } from '@mui/icons-material';
import { Grid2 as Grid } from '@mui/material';
import Card from '@mui/material/Card';
import CardActionArea from '@mui/material/CardActionArea';
import CardHeader from '@mui/material/CardHeader';
import IconButton from '@mui/material/IconButton';
import CardContent from '@mui/material/CardContent';
import EEChip from '@components/common/entreprise_edition/EEChip';
import ManagedConnectorCreation from './ManagedConnectorCreation';
import { ConnectorsStatus_data$data } from './__generated__/ConnectorsStatus_data.graphql';
import { emptyFilled } from '../../../../utils/String';
import useHelper from '../../../../utils/hooks/useHelper';
import { useFormatter } from '../../../../components/i18n';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import AlertInfo from '../../../../components/AlertInfo';

type ManagedConnectorsProps = {
  catalogs: ConnectorsStatus_data$data['catalogs'],
  managers: ConnectorsStatus_data$data['connectorManagers'],
};

export interface Catalog {
  readonly contracts: ReadonlyArray<string>;
  readonly description: string;
  readonly id: string;
  readonly name: string;
}

const Catalogs: React.FC<ManagedConnectorsProps> = ({ catalogs, managers }) => {
  const { t_i18n } = useFormatter();
  const isEnterpriseEdition = useEnterpriseEdition();
  const { isFeatureEnable } = useHelper();
  const isComposerEnable = isFeatureEnable('COMPOSER');
  const activate_manager = (managers ?? []).length > 0;
  const [catalog, setCatalog] = useState<Catalog>();

  if (!isComposerEnable) {
    return null;
  }

  return (
    <>
      <div>
        <Typography
          variant="h4"
          style={{ float: 'left', marginBottom: 15 }}
        >
          <>
            {t_i18n('Connector catalogs')}
            <EEChip feature="Connector catalogs" /> ({(managers ?? []).length} active manager)
          </>
        </Typography>
        <div className="clearfix" />
        {!isEnterpriseEdition ? (
          <Alert
            variant="outlined"
            color="secondary"
            icon={<InfoOutlined />}
          >
            {t_i18n('This feature is only available in OpenCTI Enterprise Edition.')}
          </Alert>
        ) : (
          <Grid spacing={3} container>
            {!activate_manager && (
              <Grid size={12}>
                <AlertInfo
                  content={t_i18n('You currently do not have any connector manager registered into your platform.')}
                />
              </Grid>
            )}
            {(catalogs ?? []).map((m, id) => (
              <Grid size={3} key={`${m.name}-${id}`}>
                <Card variant="outlined">
                  <CardActionArea onClick={() => setCatalog(m)}>
                    <CardHeader
                      title={m.name}
                      avatar={<HubOutlined />}
                      action={
                        <IconButton
                          size="small"
                          color="primary"
                        >
                          <Add />
                        </IconButton>
                      }
                    />
                    <CardContent>
                      <Grid container spacing={1}>
                        <Grid size={6}>
                          <Typography variant="h4" style={{ margin: 0 }}>{t_i18n('Contracts')}</Typography>
                        </Grid>
                        <Grid size={6}>
                          <Typography variant="body2">
                            {emptyFilled(m.contracts.length)}
                          </Typography>
                        </Grid>
                      </Grid>
                    </CardContent>
                  </CardActionArea>
                </Card>
              </Grid>
            ))}
          </Grid>
        )}
      </div>
      {activate_manager && catalog && (
        <ManagedConnectorCreation catalog={catalog} onClose={() => setCatalog(undefined)} />
      )}
    </>
  );
};

export default Catalogs;
