import React, { FunctionComponent } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import Typography from '@mui/material/Typography';
import Chip from '@mui/material/Chip';
import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
import { SecurityPlatformDetails_securityPlatform$data } from '@components/entities/securityPlatforms/__generated__/SecurityPlatformDetails_securityPlatform.graphql';
import { useFormatter } from '../../../../components/i18n';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import type { Theme } from '../../../../components/Theme';
import Card from '../../../../components/common/card/Card';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  chip: {
    fontSize: 12,
    lineHeight: '12px',
    backgroundColor: theme.palette.background.accent,
    textTransform: 'uppercase',
    borderRadius: 4,
    margin: '0 5px 5px 0',
  },
}));

interface SecurityPlatformDetailsComponentProps {
  securityPlatform: SecurityPlatformDetails_securityPlatform$data;
}

const SecurityPlatformDetailsComponent: FunctionComponent<SecurityPlatformDetailsComponentProps> = ({ securityPlatform }) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  return (
    <div style={{ height: '100%' }}>
      <Card title={t_i18n('Details')}>
        <Grid container={true} spacing={3}>
          <Grid item xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('Security platform type')}
            </Typography>
            <Chip
              classes={{ root: classes.chip }}
              label={securityPlatform.security_platform_type || t_i18n('Unknown')}
            />
            <Typography
              variant="h3"
              gutterBottom={true}
              style={fieldSpacingContainerStyle}
            >
              {t_i18n('Description')}
            </Typography>
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
