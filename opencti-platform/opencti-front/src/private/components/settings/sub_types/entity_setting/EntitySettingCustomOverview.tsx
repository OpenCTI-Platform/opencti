import Typography from '@mui/material/Typography';
import React from 'react';
import Paper from '@mui/material/Paper';
import Box from '@mui/material/Box';
import makeStyles from '@mui/styles/makeStyles';
import { RestartAlt } from '@mui/icons-material';
import Grid from '@mui/material/Grid';
import IconButton from '@mui/material/IconButton';
import Tooltip from '@mui/material/Tooltip';
import { useFragment } from 'react-relay';
import { SubType_subType$data } from '@components/settings/sub_types/__generated__/SubType_subType.graphql';
import EntitySettingsOverviewLayoutCustomization, {
  EntitySettingsOverviewLayoutCustomizationData,
  entitySettingsOverviewLayoutCustomizationEdit,
  entitySettingsOverviewLayoutCustomizationFragment,
} from './EntitySettingsOverviewLayoutCustomization';
import { useFormatter } from '../../../../../components/i18n';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import { EntitySettingsOverviewLayoutCustomization_entitySetting$key } from './__generated__/EntitySettingsOverviewLayoutCustomization_entitySetting.graphql';
import ErrorNotFound from '../../../../../components/ErrorNotFound';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  paper: {
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 4,
    position: 'relative',
  },
}));

interface EntitySettingCustomOverviewProps {
  entitySettingsData: SubType_subType$data['settings'];
}

const EntitySettingCustomOverview: React.FC<EntitySettingCustomOverviewProps> = ({ entitySettingsData }) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();

  const entitySetting = useFragment<EntitySettingsOverviewLayoutCustomization_entitySetting$key>(
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
              <Tooltip title={t_i18n('Reset to default layout')} >
                <RestartAlt fontSize={'small'} color={'primary'} />
              </Tooltip>
            </IconButton>
          </Box>
        </Typography>
        <Paper
          classes={{ root: classes.paper }}
          variant="outlined"
          className={'paper-for-grid'}
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
          classes={{ root: classes.paper }}
          variant="outlined"
          className={'paper-for-grid'}
        >
          <Grid container>
            {layout.map(({ key, width, label }) => (
              <Grid item xs={width} key={key}>
                <Paper
                  classes={{ root: classes.paper }}
                  className={'paper-for-grid'}
                  style={{ height: 70, padding: 0, margin: 3, display: 'flex', alignItems: 'center', justifyContent: 'center' }}
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
