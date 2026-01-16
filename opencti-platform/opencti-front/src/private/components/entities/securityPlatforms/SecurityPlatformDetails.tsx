import React, { FunctionComponent } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import Grid from '@mui/material/Grid';
import { SecurityPlatformDetails_securityPlatform$data } from '@components/entities/securityPlatforms/__generated__/SecurityPlatformDetails_securityPlatform.graphql';
import { useFormatter } from '../../../../components/i18n';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import Card from '../../../../components/common/card/Card';
import Label from '../../../../components/common/label/Label';
import Tag from '../../../../components/common/tag/Tag';

interface SecurityPlatformDetailsComponentProps {
  securityPlatform: SecurityPlatformDetails_securityPlatform$data;
}

const SecurityPlatformDetailsComponent: FunctionComponent<SecurityPlatformDetailsComponentProps> = ({ securityPlatform }) => {
  const { t_i18n } = useFormatter();
  return (
    <div style={{ height: '100%' }}>
      <Card title={t_i18n('Details')}>
        <Grid container={true} spacing={3}>
          <Grid item xs={6}>
            <Label>
              {t_i18n('Security platform type')}
            </Label>
            <Tag
              label={securityPlatform.security_platform_type || t_i18n('Unknown')}
            />
            <Label
              sx={{ mt: 2 }}
            >
              {t_i18n('Description')}
            </Label>
            <ExpandableMarkdown
              source={securityPlatform.description}
              limit={400}
            />
          </Grid>
        </Grid>
      </Card>
    </div>
  );
};

const SecurityPlatformDetails = createFragmentContainer(
  SecurityPlatformDetailsComponent,
  {
    securityPlatform: graphql`
      fragment SecurityPlatformDetails_securityPlatform on SecurityPlatform {
        id
        description
        security_platform_type
        objectLabel {
          id
          value
          color
        }
      }
    `,
  },
);

export default SecurityPlatformDetails;
