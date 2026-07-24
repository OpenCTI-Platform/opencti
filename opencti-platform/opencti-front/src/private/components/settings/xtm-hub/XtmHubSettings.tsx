import { graphql, useLazyLoadQuery } from 'react-relay';
import React, { useEffect, useState, useContext } from 'react';
import { HubOutlined, MapOutlined, RocketLaunchOutlined, VideoLibraryOutlined, WidgetsOutlined } from '@mui/icons-material';
import Typography from '@mui/material/Typography';
import XtmHubTab from '@components/settings/xtm-hub/XtmHubTab';
import Button from '@common/button/Button';
import Tag from '@common/tag/Tag';
import { useTheme } from '@mui/styles';
import { useFormatter } from '../../../../components/i18n';
import { XtmHubSettingsQuery } from './__generated__/XtmHubSettingsQuery.graphql';
import useGranted, { SETTINGS_SETMANAGEXTMHUB } from '../../../../utils/hooks/useGranted';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { UserContext } from '../../../../utils/hooks/useAuth';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import ItemBoolean from '../../../../components/ItemBoolean';
import type { Theme } from '../../../../components/Theme';
import ExperienceCard, { ExperienceHeadline } from '../experience/ExperienceCard';
import ExperienceDetailRow from '../experience/ExperienceDetailRow';
import ExperienceFeatureTile from '../experience/ExperienceFeatureTile';

export const xtmHubSettingsQuery = graphql`
  query XtmHubSettingsQuery {
    settings {
      id
      xtm_hub_registration_date
      xtm_hub_registration_status
      xtm_hub_registration_user_id
      xtm_hub_registration_user_name
      xtm_hub_last_connectivity_check
      xtm_hub_backend_is_reachable
      xtm_hub_token
    }
  }
`;

export const checkHubConnectivity = graphql`
  mutation XtmHubSettingsCheckConnectivityMutation {
    checkXTMHubConnectivity {
      status
    }
  }
`;

const XtmHubSettingsComponent = () => {
  const { t_i18n, fd } = useFormatter();
  const theme = useTheme<Theme>();
  const { settings: xtmHubSettings } = useLazyLoadQuery<XtmHubSettingsQuery>(
    xtmHubSettingsQuery,
    {},
    { fetchPolicy: 'network-only' },
  );
  const isGrantedToXtmHub = useGranted([SETTINGS_SETMANAGEXTMHUB]);
  const { isXTMHubAccessible, settings } = useContext(UserContext);

  const accent = theme.palette.xtmhub?.main ?? '#00f1bd';
  const registrationStatus = xtmHubSettings.xtm_hub_registration_status ?? undefined;
  const isRegistered = registrationStatus === 'registered' || registrationStatus === 'lost_connectivity';
  const canInteract = isGrantedToXtmHub
    && isXTMHubAccessible
    && xtmHubSettings.xtm_hub_backend_is_reachable;
  const hubUrl = settings?.platform_xtmhub_url ?? 'https://hub.filigran.io/app';

  const statusChip = (() => {
    if (registrationStatus === 'registered') {
      return <Tag label={t_i18n('Connected')} color={theme.palette.success.main} labelTextTransform="none" disableTooltip />;
    }
    if (registrationStatus === 'lost_connectivity') {
      return <Tag label={t_i18n('Connectivity lost')} color={theme.palette.error.main} labelTextTransform="none" disableTooltip />;
    }
    return <Tag label={t_i18n('Not connected')} labelTextTransform="none" disableTooltip />;
  })();

  const footer = isRegistered
    ? (
        <>
          {canInteract && (
            <XtmHubTab
              registrationStatus={registrationStatus}
              renderTrigger={(openDialog) => (
                <Button
                  variant="secondary"
                  intent="destructive"
                  onClick={openDialog}
                >
                  {t_i18n('Disconnect from XTM Hub')}
                </Button>
              )}
            />
          )}
          <Button
            gradient
            variant="secondary"
            component="a"
            href={hubUrl}
            target="_blank"
            rel="noreferrer"
          >
            {t_i18n('Go to the Hub')}
          </Button>
        </>
      )
    : (
        <>
          <Button
            variant="secondary"
            component="a"
            href="https://filigran.io/platforms/xtm-hub/"
            target="_blank"
            rel="noreferrer"
          >
            {t_i18n('Explore XTM Hub')}
          </Button>
          {canInteract && (
            <XtmHubTab
              registrationStatus={registrationStatus}
              renderTrigger={(openDialog) => (
                <Button
                  gradient
                  variant="secondary"
                  onClick={openDialog}
                >
                  {t_i18n('Connect to XTM Hub')}
                </Button>
              )}
            />
          )}
        </>
      );

  return (
    <ExperienceCard
      icon={<HubOutlined />}
      overline={t_i18n('Filigran Experience')}
      title={t_i18n('XTM Hub')}
      accent={accent}
      statusChip={statusChip}
      footer={footer}
      testId="experience-xtm-hub-card"
    >
      {isRegistered ? (
        <>
          <ExperienceHeadline>
            {t_i18n('Experiment valuable threat management resources in the XTM Hub')}
          </ExperienceHeadline>
          <div>
            <ExperienceDetailRow label={t_i18n('Connection status')}>
              <ItemBoolean
                label={registrationStatus === 'registered' ? t_i18n('Connected') : t_i18n('Connectivity lost')}
                status={registrationStatus === 'registered'}
              />
            </ExperienceDetailRow>
            {registrationStatus === 'registered' && (
              <>
                <ExperienceDetailRow label={t_i18n('Connection date')}>
                  <ItemBoolean
                    neutralLabel={fd(xtmHubSettings.xtm_hub_registration_date)}
                    status={null}
                  />
                </ExperienceDetailRow>
                <ExperienceDetailRow label={t_i18n('Connected by')} divider={false}>
                  <ItemBoolean
                    neutralLabel={xtmHubSettings.xtm_hub_registration_user_name}
                    status={null}
                  />
                </ExperienceDetailRow>
              </>
            )}
            {registrationStatus === 'lost_connectivity' && (
              <ExperienceDetailRow label={t_i18n('Last successful check')} divider={false}>
                <ItemBoolean
                  neutralLabel={fd(xtmHubSettings.xtm_hub_last_connectivity_check)}
                  status={null}
                />
              </ExperienceDetailRow>
            )}
          </div>
        </>
      ) : (
        <>
          <ExperienceHeadline>
            {t_i18n('Extend and scale your OpenCTI experience')}
          </ExperienceHeadline>
          <Typography variant="body2" color="textSecondary">
            {t_i18n("XTM Hub is a central forum to access resources, share tradecraft, and optimize the use of Filigran's products, fostering collaboration and empowering the community.")}
          </Typography>
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))',
              gap: theme.spacing(1.5),
            }}
          >
            <ExperienceFeatureTile accent={accent} icon={<RocketLaunchOutlined />} label={t_i18n('XTM Platform free trial')} />
            <ExperienceFeatureTile accent={accent} icon={<WidgetsOutlined />} label={t_i18n('Pre-built content')} />
            <ExperienceFeatureTile accent={accent} icon={<MapOutlined />} label={t_i18n('XTM Platform Roadmap')} />
            <ExperienceFeatureTile accent={accent} icon={<VideoLibraryOutlined />} label={t_i18n('Academy')} />
          </div>
        </>
      )}
    </ExperienceCard>
  );
};

const XtmHubSettings: React.FC = () => {
  const [commitCheckConnectivity] = useApiMutation(checkHubConnectivity);
  const [isCheckDone, setIsCheckDone] = useState(false);

  useEffect(() => {
    commitCheckConnectivity({ variables: {},
      onCompleted: () => {
        setIsCheckDone(true);
      } });
  }, []);

  if (!isCheckDone) {
    return <Loader variant={LoaderVariant.inElement} />;
  }

  return <XtmHubSettingsComponent />;
};

export default XtmHubSettings;
