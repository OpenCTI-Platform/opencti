import Typography from '@mui/material/Typography';
import React, { CSSProperties } from 'react';
import Paper from '@mui/material/Paper';
import Box from '@mui/material/Box';
import { RestartAlt } from '@mui/icons-material';
import Grid from '@mui/material/Grid';
import IconButton from '@common/button/IconButton';
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

  const paperStyle: CSSProperties = {
    marginTop: theme.spacing(1),
    padding: theme.spacing(2),
    borderRadius: theme.spacing(0.5),
    position: 'relative',
  };

  return layout ? (
    <>
      <Grid item xs={6}>
        <Typography variant="h4" gutterBottom={true} sx={{ marginBottom: 3 }}>
          <Box sx={{ display: 'inline-flex', alignItems: 'center' }}>
            <span>{t_i18n('Overview layout customization')}</span>
            <IconButton
              onClick={() => resetLayout()}
              aria-haspopup="true"
              sx={{ marginLeft: 1 }}
              size="small"
              color="primary"
            >
              <Tooltip title={t_i18n('Reset to default layout')}>
                <RestartAlt fontSize="small" color="primary" />
              </Tooltip>
            </IconButton>
          </Box>
        </Typography>
        <Paper
          variant="outlined"
          className="paper-for-grid"
          style={paperStyle}
        >
          <EntitySettingsOverviewLayoutCustomization
            entitySettingsData={entitySetting as EntitySettingsOverviewLayoutCustomizationData}
          />
        </Paper>
      </Grid>
      <Grid item xs={6}>
        <Typography variant="h4" gutterBottom={true} sx={{ marginTop: 1, marginBottom: 2 }}>
          {t_i18n('Preview')}
        </Typography>
        <Paper
          variant="outlined"
          className="paper-for-grid"
          style={paperStyle}
        >
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
        </Paper>
      </Grid>
    </>
  ) : null;
};

export default EntitySettingCustomOverview;
