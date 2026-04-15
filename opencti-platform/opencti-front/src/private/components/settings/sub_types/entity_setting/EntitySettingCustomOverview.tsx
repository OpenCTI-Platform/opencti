import IconButton from '@common/button/IconButton';
import { RestartAlt } from '@mui/icons-material';
import Grid from '@mui/material/Grid2';
import Paper from '@mui/material/Paper';
import Tooltip from '@mui/material/Tooltip';
import { useTheme } from '@mui/styles';
import { useFragment } from 'react-relay';
import ErrorNotFound from '../../../../../components/ErrorNotFound';
import type { Theme } from '../../../../../components/Theme';
import Card from '../../../../../components/common/card/Card';
import { useFormatter } from '../../../../../components/i18n';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import { useSubTypeOutletContext } from '../SubTypeOutletContext';
import EntitySettingsOverviewLayoutCustomization, {
  EntitySettingsOverviewLayoutCustomizationData,
  entitySettingsOverviewLayoutCustomizationEdit,
  entitySettingsOverviewLayoutCustomizationFragment,
} from './EntitySettingsOverviewLayoutCustomization';
import { EntitySettingsOverviewLayoutCustomization_entitySetting$key } from './__generated__/EntitySettingsOverviewLayoutCustomization_entitySetting.graphql';

const EntitySettingCustomOverview = () => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const { subType } = useSubTypeOutletContext();

  const entitySetting = useFragment(
    entitySettingsOverviewLayoutCustomizationFragment,
    (subType?.settings ?? null) as EntitySettingsOverviewLayoutCustomization_entitySetting$key | null,
  );

  const [commitReset] = useApiMutation((entitySettingsOverviewLayoutCustomizationEdit));

  if (!subType) return <ErrorNotFound />;
  if (!subType.settings) return <ErrorNotFound />;

  if (!entitySetting) {
    return <ErrorNotFound />;
  }

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

  if (!layout) return null;

  return (
    <Grid container spacing={2}>
      <Grid size={6}>
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
      <Grid size={6}>
        <Card title={t_i18n('Preview')}>
          <Grid container>
            {layout.map(({ key, width, label }) => (
              <Grid size={width} key={key}>
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
    </Grid>
  );
};

export default EntitySettingCustomOverview;
