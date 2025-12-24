import React from 'react';
import Paper from '@mui/material/Paper';
import { RestartAlt } from '@mui/icons-material';
import Grid from '@mui/material/Grid';
import IconButton from '@mui/material/IconButton';
import Tooltip from '@mui/material/Tooltip';
import { useFragment } from 'react-relay';
import { useTheme } from '@mui/styles';
import EntitySettingsOverviewLayoutCustomization, {
  EntitySettingsOverviewLayoutCustomizationData,
  entitySettingsOverviewLayoutCustomizationEdit,
  entitySettingsOverviewLayoutCustomizationFragment,
} from './EntitySettingsOverviewLayoutCustomization';
import { useFormatter } from '../../../../../components/i18n';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import { EntitySettingsOverviewLayoutCustomization_entitySetting$key } from './__generated__/EntitySettingsOverviewLayoutCustomization_entitySetting.graphql';
import ErrorNotFound from '../../../../../components/ErrorNotFound';
import type { Theme } from '../../../../../components/Theme';
import Card from '../../../../../components/common/card/Card';

interface EntitySettingCustomOverviewProps {
  entitySettingsData: EntitySettingsOverviewLayoutCustomization_entitySetting$key;
}

const EntitySettingCustomOverview: React.FC<EntitySettingCustomOverviewProps> = ({ entitySettingsData }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const entitySetting = useFragment(
    entitySettingsOverviewLayoutCustomizationFragment,
    entitySettingsData,
  );

  if (!entitySetting) {
    return <ErrorNotFound />;
  }

  const [commitReset] = useApiMutation((entitySettingsOverviewLayoutCustomizationEdit));
  const resetLayout = () => {
    commitReset({
      variables: {
        ids: [entitySetting.id],
        input: {
          key: 'overview_layout_customization',
          value: [undefined],
        },
      },
    });
  };

  const layout = entitySetting.overview_layout_customization;

  return layout ? (
    <>
      <Grid item xs={6}>
        <Card
          title={t_i18n('Overview layout customization')}
          action={(
            <IconButton
              onClick={() => resetLayout()}
              aria-haspopup="true"
              size="small"
              color="primary"
            >
              <Tooltip title={t_i18n('Reset to default layout')}>
                <RestartAlt fontSize="small" color="primary" />
              </Tooltip>
            </IconButton>
          )}
        >
          <EntitySettingsOverviewLayoutCustomization
            entitySettingsData={entitySetting as EntitySettingsOverviewLayoutCustomizationData}
          />
        </Card>
      </Grid>
      <Grid item xs={6}>
        <Card title={t_i18n('Preview')}>
          <Grid container>
            {layout.map(({ key, width, label }) => (
              <Grid item xs={width} key={key}>
                <Paper
                  className="paper-for-grid"
                  style={{
                    borderRadius: 4,
                    position: 'relative',
                    height: 70,
                    padding: 0,
                    margin: 3,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    boxShadow: 'none',
                    border: `0.5px solid ${theme.palette.border.primary}`,
                  }}
                >
                  {t_i18n(label)}
                </Paper>
              </Grid>
            ))}
          </Grid>
        </Card>
      </Grid>
    </>
  ) : null;
};

export default EntitySettingCustomOverview;
