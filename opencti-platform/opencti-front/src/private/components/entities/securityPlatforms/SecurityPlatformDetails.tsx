import React, { FunctionComponent } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import { SecurityPlatformDetails_securityPlatform$data } from '@private/components/entities/securityPlatforms/__generated__/SecurityPlatformDetails_securityPlatform.graphql';
import { useFormatter } from '../../../../components/i18n';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import type { Theme } from '../../../../components/Theme';
import { Chip, Grid, Paper, Typography } from '@components';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  paper: {
    marginTop: theme.spacing(1),
    padding: '15px',
    borderRadius: 6,
  },
  chip: {
    fontSize: 12,
    lineHeight: '12px',
    backgroundColor: theme.palette.background.accent,
    color: theme.palette.text?.primary,
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
      <Typography variant="h4" gutterBottom={true}>
        {t_i18n('Details')}
      </Typography>
      <Paper classes={{ root: classes.paper }} className={'paper-for-grid'} variant="outlined">
        <Grid container={true} spacing={3}>
          <Grid size={6}>
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
      </Paper>
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
