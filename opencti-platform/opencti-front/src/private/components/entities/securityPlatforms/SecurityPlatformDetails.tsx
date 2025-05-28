import React, { FunctionComponent } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Chip from '@mui/material/Chip';
import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
import { SecurityPlatformDetails_securityPlatform$data } from '@components/entities/securityPlatforms/__generated__/SecurityPlatformDetails_securityPlatform.graphql';
import { useFormatter } from '../../../../components/i18n';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import type { Theme } from '../../../../components/Theme';
import ItemScore from '../../../../components/ItemScore';

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
    height: 25,
    marginRight: 7,
    textTransform: 'uppercase',
    borderRadius: 4,
    width: 150,
    backgroundColor: 'rgba(229,152,137, 0.08)',
    color: '#e59889',
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
          <Grid item xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('Organization type')}
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
            <Typography
              variant="h3"
              gutterBottom={true}
              style={{ marginTop: 20 }}
            >
              {t_i18n('Score')}
            </Typography>
            <ItemScore score={securityPlatform.x_opencti_score} />
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
        x_opencti_score
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
