import React, { FunctionComponent, useState } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import Grid from '@mui/material/Grid';
import XtmHubSettings from '@components/settings/xtm-hub/XtmHubSettings';
import SupportPackages from '@components/settings/support/SupportPackages';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import { Experience$key } from '@components/settings/__generated__/Experience.graphql';
import Typography from '@mui/material/Typography';
import DangerZoneBlock from '@components/common/danger_zone/DangerZoneBlock';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import Paper from '@mui/material/Paper';
import Alert from '@mui/material/Alert';
import EnterpriseEditionButton from '@components/common/entreprise_edition/EnterpriseEditionButton';
import List from '@mui/material/List';
import { useTheme } from '@mui/styles';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import * as Yup from 'yup';
import Box from '@mui/material/Box';
import { ExperienceQuery } from './__generated__/ExperienceQuery.graphql';
import Transition from '../../../components/Transition';
import useSensitiveModifications from '../../../utils/hooks/useSensitiveModifications';
import { useFormatter } from '../../../components/i18n';
import Breadcrumbs from '../../../components/Breadcrumbs';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../components/Loader';
import ItemBoolean from '../../../components/ItemBoolean';
import type { Theme } from '../../../components/Theme';
import { FieldOption } from '../../../utils/field';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import useGranted, { SETTINGS_SETPARAMETERS, SETTINGS_SUPPORT } from '../../../utils/hooks/useGranted';

const useStyles = makeStyles<Theme>((theme) => ({
  container: {
    margin: 0,
    padding: '0 0 50px 0',
  },
  paper: {
    marginTop: theme.spacing(1),
    padding: 20,
    borderRadius: 4,
  },
}));

const ExperienceFragment = graphql`
  fragment Experience on Settings {
    id
    platform_enterprise_edition {
      license_enterprise
      license_by_configuration
      license_valid_cert
      license_validated
      license_expiration_prevention
      license_customer
      license_expiration_date
      license_start_date
      license_platform_match
      license_expired
      license_type
      license_creator
      license_global
    }
  }
`;

const experienceQuery = graphql`
  query ExperienceQuery {
    settings {
      ...Experience
    }
  }
`;

interface ExperienceComponentProps {
  queryRef: PreloadedQuery<ExperienceQuery>;
}

export const experienceFieldPatch = graphql`
  mutation ExperienceFieldPatchMutation($id: ID!, $input: [EditInput]!) {
    settingsEdit(id: $id) {
      fieldPatch(input: $input) {
        ...Experience
      }
    }
  }
`;

const ExperienceComponent: FunctionComponent<ExperienceComponentProps> = ({ queryRef }) => {
  const { t_i18n, fldt } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Filigran Experience | Settings'));
  const theme = useTheme<Theme>();
  const classes = useStyles();
  const isGrantedToParameters = useGranted([SETTINGS_SETPARAMETERS]);
  const isGrantedToSupport = useGranted([SETTINGS_SUPPORT]);
  const data = usePreloadedQuery(experienceQuery, queryRef);
  const settings = useFragment<Experience$key>(ExperienceFragment, data.settings);
  const isEnterpriseEditionActivated = settings.platform_enterprise_edition.license_enterprise;
  const isEnterpriseEditionByConfig = settings.platform_enterprise_edition.license_by_configuration;
  const { isAllowed } = useSensitiveModifications('ce_ee_toggle');
  const [openEEChanges, setOpenEEChanges] = useState(false);
  const experienceValidation = () => Yup.object().shape({
    enterprise_license: Yup.string().nullable(),
  });
  const [commitField] = useApiMutation(experienceFieldPatch);
  const handleSubmitField = (name: string, value: string | string[] | FieldOption | null) => {
    experienceValidation()
      .validateAt(name, { [name]: value })
      .then(() => {
        commitField({
          variables: {
            id: settings.id,
            input: {
              key: name,
              value: ((value as FieldOption)?.value ?? value) || '',
            },
          },
        });
      })
      .catch(() => false);
  };

  return (
    <div className={classes.container}>
      <Breadcrumbs elements={[{ label: t_i18n('Settings') }, { label: t_i18n('Filigran Experience'), current: true }]} />
      <Grid container={true} spacing={3} style={{ marginBottom: 23 }}>
        {isEnterpriseEditionActivated ? (
          <Grid item xs={6}>
            <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
              {t_i18n('Enterprise Edition')}
            </Typography>
            {!isEnterpriseEditionByConfig && isGrantedToParameters && (
            <div style={{ float: 'right', marginTop: theme.spacing(-2.6), position: 'relative' }}>
              <DangerZoneBlock
                type='ce_ee_toggle'
                sx={{
                  root: { border: 'none', padding: 0, margin: 0 },
                  title: { position: 'absolute', zIndex: 2, left: 4, top: 9, fontSize: 8 },
                }}
              >
                {({ disabled }) => (
                  <>
                    <Button
                      size="small"
                      variant="outlined"
                      color='dangerZone'
                      onClick={() => setOpenEEChanges(true)}
                      disabled={disabled}
                      style={{
                        color: isAllowed ? theme.palette.dangerZone.text?.primary : theme.palette.dangerZone.text?.disabled,
                        borderColor: theme.palette.dangerZone.main,
                      }}
                    >
                      {t_i18n('Disable Enterprise Edition')}
                    </Button>
                    <Dialog
                      slotProps={{ paper: { elevation: 1 } }}
                      open={openEEChanges}
                      keepMounted
                      slots={{ transition: Transition }}
                      onClose={() => setOpenEEChanges(false)}
                    >
                      <DialogTitle>{t_i18n('Disable Enterprise Edition')}</DialogTitle>
                      <DialogContent>
                        <DialogContentText>
                          <Alert
                            severity="warning"
                            variant="outlined"
                            color="dangerZone"
                            style={{ borderColor: theme.palette.dangerZone.main }}
                          >
                            {t_i18n('You are about to disable the "Enterprise Edition" mode. Please note that this action will disable access to certain advanced features (organization segregation, automation, file indexing etc.).')}
                            <br /><br />
                            <strong>{t_i18n('However, your existing data will remain intact and will not be lost.')}</strong>
                          </Alert>
                        </DialogContentText>
                      </DialogContent>
                      <DialogActions>
                        <Button
                          onClick={() => {
                            setOpenEEChanges(false);
                          }}
                        >
                          {t_i18n('Cancel')}
                        </Button>
                        <Button
                          color="secondary"
                          onClick={() => {
                            setOpenEEChanges(false);
                            handleSubmitField('enterprise_license', '');
                          }}
                        >
                          {t_i18n('Validate')}
                        </Button>
                      </DialogActions>
                    </Dialog>
                  </>
                )}
              </DangerZoneBlock>
            </div>
            )}
            {!isEnterpriseEditionByConfig && isGrantedToParameters && (
              <div style={{ float: 'right', marginRight: theme.spacing(1), marginTop: theme.spacing(-2), position: 'relative' }}>
                <EnterpriseEditionButton inLine={true} title={t_i18n('Update license')} />
              </div>
            )}
            <div className="clearfix" />
            <Paper
              classes={{ root: classes.paper }}
              variant="outlined"
              className='paper-for-grid'
            >
              <List style={{ marginTop: -20 }}>
                <ListItem divider={true}>
                  <ListItemText primary={t_i18n('Organization')} />
                  <ItemBoolean
                    variant="xlarge"
                    neutralLabel={settings.platform_enterprise_edition.license_customer}
                    status={null}
                  />
                </ListItem>
                <ListItem divider={true}>
                  <ListItemText primary={t_i18n('Scope')} />
                  <ItemBoolean
                    variant="xlarge"
                    neutralLabel={settings.platform_enterprise_edition.license_global ? t_i18n('Global') : t_i18n('Current instance')}
                    status={null}
                  />
                </ListItem>
                {!settings.platform_enterprise_edition.license_expired && settings.platform_enterprise_edition.license_expiration_prevention && (
                <ListItem divider={false}>
                  <Alert severity="warning" variant="outlined" style={{ width: '100%' }}>
                    {t_i18n('Your Enterprise Edition license will expire in less than 3 months.')}
                  </Alert>
                </ListItem>
                )}
                {!settings.platform_enterprise_edition.license_validated && settings.platform_enterprise_edition.license_valid_cert && (
                <ListItem divider={false}>
                  <Alert severity="error" variant="outlined" style={{ width: '100%' }}>
                    {t_i18n('Your Enterprise Edition license is expired. Please contact your Filigran representative.')}
                  </Alert>
                </ListItem>
                )}
                <ListItem divider={true}>
                  <ListItemText primary={t_i18n('Start date')}/>
                  <ItemBoolean
                    variant="xlarge"
                    label={fldt(settings.platform_enterprise_edition.license_start_date)}
                    status={!settings.platform_enterprise_edition.license_expired}
                  />
                </ListItem>
                <ListItem divider={true}>
                  <ListItemText primary={t_i18n('Expiration date')}/>
                  <ItemBoolean
                    variant="xlarge"
                    label={fldt(settings.platform_enterprise_edition.license_expiration_date)}
                    status={!settings.platform_enterprise_edition.license_expired}
                  />
                </ListItem>
                <ListItem divider={!settings.platform_enterprise_edition.license_expiration_prevention}>
                  <ListItemText primary={t_i18n('License type')}/>
                  <ItemBoolean
                    variant="xlarge"
                    neutralLabel={settings.platform_enterprise_edition.license_type}
                    status={null}
                  />
                </ListItem>
              </List>
            </Paper>
          </Grid>
        ) : (
          <Grid item xs={6}>
            <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
              {t_i18n('Enterprise Edition')}
            </Typography>
            <div style={{ float: 'right', marginTop: theme.spacing(-2.1), position: 'relative' }}>
              {!isEnterpriseEditionActivated && isGrantedToParameters && (
                <EnterpriseEditionButton inLine={true} />
              )}
            </div>
            <div className="clearfix"/>
            <Paper
              classes={{ root: classes.paper }}
              className='paper-for-grid'
              variant="outlined"
            >
              <Box>
                <Typography variant="h6">
                  {t_i18n('Enable powerful features with OpenCTI Enterprise Edition')}
                </Typography>
                <p>{t_i18n('OpenCTI Enterprise Edition (EE) provides highly demanding organizations with a version that includes additional and powerful features, which require specific investments in research and development.')}</p>
                <List sx={{ listStyleType: 'disc', marginLeft: 4 }}>
                  <li>{t_i18n('Agentic AI capabilities')}</li>
                  <li>{t_i18n('Playbooks and automation')}</li>
                  <li>{t_i18n('Full text indexing')}</li>
                  <li>{t_i18n('And many more features...')}</li>
                </List>
                <Button color="ee" variant="outlined" component="a" href="https://filigran.io/offerings/opencti-enterprise-edition/" target="_blank" rel="noreferrer" style={{ marginTop: 10, marginBottom: 10 }}>
                  {t_i18n('Discover OpenCTI EE')}
                </Button>
              </Box>
            </Paper>
          </Grid>
        )}
        <Grid item xs={6}>
          <XtmHubSettings />
        </Grid>
        {isGrantedToSupport && (
          <Grid item xs={12} style={{ marginTop: 15 }}>
            <SupportPackages />
          </Grid>
        )}
      </Grid>
    </div>
  );
};

const Experience: FunctionComponent = () => {
  const queryRef = useQueryLoading<ExperienceQuery>(experienceQuery, {});
  return (
    <>
      {queryRef && (
        <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <ExperienceComponent queryRef={queryRef} />
        </React.Suspense>
      )}
    </>
  );
};

export default Experience;
