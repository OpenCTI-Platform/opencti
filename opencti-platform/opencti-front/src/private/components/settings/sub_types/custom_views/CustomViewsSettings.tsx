import Grid from '@mui/material/Grid';
import Card from '@common/card/Card';
import { useFormatter } from '../../../../../components/i18n';
import { useSubTypeOutletContext } from '../SubTypeOutletContext';
import CustomViewsSettingsDataTable from './CustomViewsSettingsDataTable';

/**
 * Custom Views settings page.
 */
const CustomViewsSettings = () => {
  const { t_i18n } = useFormatter();
  const { subType } = useSubTypeOutletContext();

  return (
    <Grid item xs={12}>
      <Card
        title={t_i18n('Custom Views')}
        sx={{
          // Compensate existing top padding from data table header
          //  to avoid the feeling of having too much empty space.
          pt: 2,
        }}
      >
        <CustomViewsSettingsDataTable targetType={subType.id} />
      </Card>
    </Grid>
  );
};

export default CustomViewsSettings;
