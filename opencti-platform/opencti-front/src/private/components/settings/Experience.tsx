import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import Tag from '@common/tag/Tag';
import EnterpriseEditionButton from '@components/common/entreprise_edition/EnterpriseEditionButton';
import { Experience$key } from '@components/settings/__generated__/Experience.graphql';
import { ExperienceFieldPatchMutation$data } from '@components/settings/__generated__/ExperienceFieldPatchMutation.graphql';
import getEEWarningMessage from '@components/settings/EEActivation';
import SupportPackages from '@components/settings/support/SupportPackages';
import XtmHubSettings from '@components/settings/xtm-hub/XtmHubSettings';
import { AutoAwesomeOutlined, ManageSearchOutlined, MoreHorizOutlined, PrecisionManufacturingOutlined, RocketLaunchOutlined } from '@mui/icons-material';
import { Stack, Switch } from '@mui/material';
import Alert from '@mui/material/Alert';
import Box from '@mui/material/Box';
import DialogActions from '@mui/material/DialogActions';
import Grid from '@mui/material/Grid';
import Typography from '@mui/material/Typography';
import { useTheme } from '@mui/styles';
import React, { ChangeEvent, FunctionComponent, useState } from 'react';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import * as Yup from 'yup';
import Breadcrumbs from '../../../components/Breadcrumbs';
import { useFormatter } from '../../../components/i18n';
import ItemBoolean from '../../../components/ItemBoolean';
import Loader, { LoaderVariant } from '../../../components/Loader';
import type { Theme } from '../../../components/Theme';
import { FieldOption } from '../../../utils/field';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import useAuth from '../../../utils/hooks/useAuth';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import useGranted, { SETTINGS_SETPARAMETERS, SETTINGS_SUPPORT } from '../../../utils/hooks/useGranted';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import DangerZoneButton from '../common/danger_zone/DangerZoneButton';
import { ExperienceQuery } from './__generated__/ExperienceQuery.graphql';
import ExperienceCard, { ExperienceHeadline } from './experience/ExperienceCard';
import ExperienceDetailRow from './experience/ExperienceDetailRow';
import ExperienceFeatureTile from './experience/ExperienceFeatureTile';
import ValidateTermsOfUseDialog from './ValidateTermsOfUseDialog';
import { useChatbot } from '@components/chatbox/ChatbotContext';

export enum CGUStatus {
  pending = 'pending',
  disabled = 'disabled',
  enabled = 'enabled',
}

const ExperienceFragment = graphql`
  fragment Experience on Settings {
    id
    platform_type
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
    platform_ai_enabled
    filigran_chatbot_ai_cgu_status
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
        platform_enterprise_edition {
          license_validated
        }
      }
    }
  }
`;

const ExperienceComponent: FunctionComponent<ExperienceComponentProps> = ({ queryRef }) => {
  const { t_i18n, fldt } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Filigran Experience | Settings'));
  const theme = useTheme<Theme>();
  const { settings: { filigran_chatbot_ai_cgu_status, platform_ai_enabled } } = useAuth();
  const isGrantedToParameters = useGranted([SETTINGS_SETPARAMETERS]);
  const { xtmOneConfigured } = useChatbot();
  const isGrantedToSupport = useGranted([SETTINGS_SUPPORT]);
  const data = usePreloadedQuery(experienceQuery, queryRef);
  const settings = useFragment<Experience$key>(ExperienceFragment, data.settings);
  const enterpriseEdition = settings.platform_enterprise_edition;
  const isEnterpriseEditionActivated = enterpriseEdition.license_enterprise;
  const isEnterpriseEditionByConfig = enterpriseEdition.license_by_configuration;
  const [openEEChanges, setOpenEEChanges] = useState(false);
  const [openValidateTermsOfUse, setOpenValidateTermsOfUse] = useState(false);
  const experienceValidation = () => Yup.object().shape({
    enterprise_license: Yup.string().nullable(),
    filigran_chatbot_ai_cgu_status: Yup.mixed<CGUStatus>().oneOf([CGUStatus.enabled, CGUStatus.disabled, CGUStatus.pending]),
    platform_ai_enabled: Yup.boolean(),
  });
  const isLtsPlatform = settings.platform_type === 'LTS';
  const [commitField] = useApiMutation(experienceFieldPatch);
  const handleSubmitField = (name: string, value: string | string[] | FieldOption | null | boolean) => {
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
          onCompleted: (response) => {
            const resData = response as ExperienceFieldPatchMutation$data;
            // If platform is LTS but license is no longer valid, need to refresh to force the license.
            if (isLtsPlatform && !resData.settingsEdit?.fieldPatch?.platform_enterprise_edition.license_validated) {
              window.location.reload();
            }
          },
        });
      })
      .catch(() => false);
  };

  const handleCGUStatusChange = (event: ChangeEvent<HTMLInputElement>) => {
    if (event.target.checked) {
      setOpenValidateTermsOfUse(true);
    } else {
      handleSubmitField('filigran_chatbot_ai_cgu_status', CGUStatus.disabled);
    }
  };

  const handlePlatformAiEnabledChange = (event: ChangeEvent<HTMLInputElement>) => {
    handleSubmitField('platform_ai_enabled', event.target.checked);
  };

  const handleValidateTermsOfUse = () => {
    setOpenValidateTermsOfUse(false);
  };

  const eeAccent = theme.palette.ee.main ?? '#00f18d';

  const eeStatusChip = (() => {
    if (!isEnterpriseEditionActivated) {
      return <Tag label={t_i18n('Community edition')} labelTextTransform="none" disableTooltip />;
    }
    if (enterpriseEdition.license_expired) {
      return <Tag label={t_i18n('Expired')} color={theme.palette.error.main} labelTextTransform="none" disableTooltip />;
    }
    return <Tag label={t_i18n('Activated')} color={theme.palette.success.main} labelTextTransform="none" disableTooltip />;
  })();

  const eeActivatedFooter = !isEnterpriseEditionByConfig && isGrantedToParameters
    ? (
        <>
          <DangerZoneButton
            sensitiveType="ce_ee_toggle"
            size="default"
            onClick={() => setOpenEEChanges(true)}
          >
            {t_i18n('Disable Enterprise Edition')}
          </DangerZoneButton>
          <EnterpriseEditionButton inLine size="default" title="Update license" />
        </>
      )
    : undefined;

  const eeCommunityFooter = isGrantedToParameters
    ? <EnterpriseEditionButton inLine size="default" title="Try OpenCTI Enterprise Edition" />
    : (
        <Button
          variant="secondary"
          component="a"
          href="https://filigran.io/offerings/opencti-enterprise-edition/"
          target="_blank"
          rel="noopener noreferrer"
        >
          {t_i18n('Discover OpenCTI EE')}
        </Button>
      );

  const eeActivatedBody = (
    <div>
      <ExperienceDetailRow label={t_i18n('Organization')}>
        <ItemBoolean
          neutralLabel={enterpriseEdition.license_customer}
          status={null}
        />
      </ExperienceDetailRow>
      <ExperienceDetailRow label={t_i18n('Scope')}>
        <ItemBoolean
          neutralLabel={enterpriseEdition.license_global ? t_i18n('Global') : t_i18n('Current instance')}
          status={null}
        />
      </ExperienceDetailRow>
      <ExperienceDetailRow label={t_i18n('Start date')}>
        <ItemBoolean
          label={fldt(enterpriseEdition.license_start_date)}
          status={!enterpriseEdition.license_expired}
        />
      </ExperienceDetailRow>
      <ExperienceDetailRow label={t_i18n('Expiration date')}>
        <ItemBoolean
          label={fldt(enterpriseEdition.license_expiration_date)}
          status={!enterpriseEdition.license_expired}
        />
      </ExperienceDetailRow>
      <ExperienceDetailRow
        label={t_i18n('License type')}
        divider={isGrantedToParameters || !xtmOneConfigured}
      >
        <ItemBoolean
          neutralLabel={enterpriseEdition.license_type}
          status={null}
        />
      </ExperienceDetailRow>
      {isGrantedToParameters && (
        <ExperienceDetailRow
          divider={!xtmOneConfigured}
          label={(
            <Stack direction="row" alignItems="center" gap={1}>
              <Typography variant="body2" color="textSecondary">
                {xtmOneConfigured ? t_i18n('XTM One (Agentic AI)') : t_i18n('Agentic AI (Ariane Assistant)')}
              </Typography>
              {!xtmOneConfigured && (
                <Tag
                  label={t_i18n('Preview')}
                  tooltipTitle={t_i18n('This feature is in preview and will improve over time with user\'s feedback.')}
                />
              )}
            </Stack>
          )}
        >
          {filigran_chatbot_ai_cgu_status === CGUStatus.pending ? (
            <Button
              size="small"
              variant="secondary"
              onClick={() => setOpenValidateTermsOfUse(true)}
              style={{ lineHeight: '12px', width: 200 }}
            >
              {t_i18n('Validate the Filigran AI Terms')}
            </Button>
          ) : (
            <Box sx={{ marginBlock: -0.75 }}>
              <Switch
                checked={filigran_chatbot_ai_cgu_status === CGUStatus.enabled}
                onChange={handleCGUStatusChange}
              />
            </Box>
          )}
          {openValidateTermsOfUse && (
            <ValidateTermsOfUseDialog open={openValidateTermsOfUse} onClose={handleValidateTermsOfUse} />
          )}
        </ExperienceDetailRow>
      )}
      {!xtmOneConfigured && (
        <ExperienceDetailRow label={t_i18n('Generative AI (AI Insight, NLQ)')} divider={false}>
          <Box sx={{ marginBlock: -0.75 }}>
            <Switch
              checked={platform_ai_enabled}
              onChange={handlePlatformAiEnabledChange}
            />
          </Box>
        </ExperienceDetailRow>
      )}
      {!enterpriseEdition.license_expired && enterpriseEdition.license_expiration_prevention && (
        <Alert severity="warning" variant="outlined" style={{ width: '100%', marginTop: theme.spacing(2) }}>
          {t_i18n('Your Enterprise Edition license will expire in less than 3 months.')}
        </Alert>
      )}
      {!enterpriseEdition.license_validated && enterpriseEdition.license_valid_cert && (
        <Alert severity="error" variant="outlined" style={{ width: '100%', marginTop: theme.spacing(2) }}>
          {t_i18n('Your Enterprise Edition license is expired. Please contact your Filigran representative.')}
        </Alert>
      )}
    </div>
  );

  const eeCommunityBody = (
    <>
      <ExperienceHeadline>
        {t_i18n('Enable powerful features with OpenCTI Enterprise Edition')}
      </ExperienceHeadline>
      <Typography variant="body2" color="textSecondary">
        {t_i18n('OpenCTI Enterprise Edition (EE) provides highly demanding organizations with a version that includes additional and powerful features, which require specific investments in research and development.')}
      </Typography>
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))',
          gap: theme.spacing(1.5),
        }}
      >
        <ExperienceFeatureTile accent={eeAccent} icon={<AutoAwesomeOutlined />} label={t_i18n('Agentic AI capabilities')} />
        <ExperienceFeatureTile accent={eeAccent} icon={<PrecisionManufacturingOutlined />} label={t_i18n('Playbooks and automation')} />
        <ExperienceFeatureTile accent={eeAccent} icon={<ManageSearchOutlined />} label={t_i18n('Full text indexing')} />
        <ExperienceFeatureTile accent={eeAccent} icon={<MoreHorizOutlined />} label={t_i18n('And many more features...')} />
      </div>
    </>
  );

  return (
    <div style={{ margin: 0, padding: '0 0 50px 0' }} data-testid="experience-page">
      <Breadcrumbs elements={[{ label: t_i18n('Settings') }, { label: t_i18n('Filigran Experience'), current: true }]} />
      <Grid container={true} spacing={3} alignItems="stretch" style={{ marginBottom: 23 }}>
        <Grid item xs={6}>
          <ExperienceCard
            icon={<RocketLaunchOutlined />}
            overline={t_i18n('Filigran Experience')}
            title={t_i18n('Enterprise Edition')}
            accent={eeAccent}
            statusChip={eeStatusChip}
            footer={isEnterpriseEditionActivated ? eeActivatedFooter : eeCommunityFooter}
            testId="experience-enterprise-edition-card"
          >
            {isEnterpriseEditionActivated ? eeActivatedBody : eeCommunityBody}
          </ExperienceCard>
          <Dialog
            open={openEEChanges}
            onClose={() => setOpenEEChanges(false)}
            title={t_i18n('Disable Enterprise Edition')}
          >
            <Alert
              severity="warning"
              variant="outlined"
              color="dangerZone"
              style={{ borderColor: theme.palette.dangerZone.main }}
            >
              {t_i18n(getEEWarningMessage(isLtsPlatform))}
              <br /><br />
              <strong>{t_i18n('However, your existing data will remain intact and will not be lost.')}</strong>
            </Alert>
            <DialogActions>
              <Button
                variant="secondary"
                onClick={() => {
                  setOpenEEChanges(false);
                }}
              >
                {t_i18n('Cancel')}
              </Button>
              <Button
                onClick={() => {
                  setOpenEEChanges(false);
                  handleSubmitField('enterprise_license', '');
                }}
              >
                {t_i18n('Validate')}
              </Button>
            </DialogActions>
          </Dialog>
        </Grid>
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
