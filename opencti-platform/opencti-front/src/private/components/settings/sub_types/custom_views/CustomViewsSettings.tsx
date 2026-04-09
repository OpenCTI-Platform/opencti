import { graphql, useFragment } from 'react-relay';
import Grid from '@mui/material/Grid';
import Card from '@common/card/Card';
import { useFormatter } from '../../../../../components/i18n';
import { useSubTypeOutletContext } from '../SubTypeOutletContext';
import CustomViewsSettingsDataTable from './CustomViewsSettingsDataTable';
import { CustomViewsSettings_customViews$key } from './__generated__/CustomViewsSettings_customViews.graphql';

const customViewsFragment = graphql`
  fragment CustomViewsSettings_customViews on CustomViewsSettings {
    customViews {
      id
      name
      description
      created_at
      updated_at
    }
  }
`;

/**
 * Custom Views settings page.
 */
const CustomViewsSettings = () => {
  const { t_i18n } = useFormatter();
  const { customViewsSettings, subType } = useSubTypeOutletContext();
  const { customViews } = useFragment(
    customViewsFragment,
    customViewsSettings as CustomViewsSettings_customViews$key,
  );

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
        <CustomViewsSettingsDataTable customViews={customViews} targetType={subType.id} />
      </Card>
    </Grid>
  );
};

export default CustomViewsSettings;
