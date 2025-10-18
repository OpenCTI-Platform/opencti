import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import makeStyles from '@mui/styles/makeStyles';
import Grid from '@mui/material/Grid';
import { Theme } from '@mui/material/styles/createTheme';
import SecurityCoverageInformation from '@components/analyses/security_coverages/SecurityCoverageInformation';
import Button from '@mui/material/Button';
import { Link } from 'react-router-dom';
import { useFormatter } from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import { SecurityCoverageDetails_securityCoverage$key } from './__generated__/SecurityCoverageDetails_securityCoverage.graphql';
import SecurityCoverageSecurityPlatforms from './SecurityCoverageSecurityPlatforms';
import SecurityCoverageVulnerabilities from './SecurityCoverageVulnerabilities';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  paper: {
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 4,
  },
  coveredObject: {
    display: 'flex',
    alignItems: 'center',
    gap: theme.spacing(1),
    marginTop: theme.spacing(1),
  },
}));

const securityCoverageDetailsFragment = graphql`
  fragment SecurityCoverageDetails_securityCoverage on SecurityCoverage {
    id
    name
    description
    coverage_last_result
    coverage_valid_from
    coverage_valid_to
    coverage_information {
      coverage_name
      coverage_score
    }
    objectCovered {
      id
      entity_type
      representative {
          main
      }
    }
    ...SecurityCoverageSecurityPlatforms_securityCoverage
    ...SecurityCoverageVulnerabilities_securityCoverage
  }
`;

interface SecurityCoverageDetailsProps {
  securityCoverage: SecurityCoverageDetails_securityCoverage$key;
}

const SecurityCoverageDetails: FunctionComponent<SecurityCoverageDetailsProps> = ({
  securityCoverage,
}) => {
  const classes = useStyles();
  const { t_i18n, fd } = useFormatter();
  const data = useFragment(securityCoverageDetailsFragment, securityCoverage);

  return (
    <div style={{ height: '100%' }}>
      <Typography variant="h4" gutterBottom={true}>
        {t_i18n('Details')}
      </Typography>
      <Paper classes={{ root: classes.paper }} variant="outlined">
        <Grid container={true} spacing={3}>
          <Grid item xs={12}>
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('Name')}
            </Typography>
            {data.name || '-'}
          </Grid>
          <Grid item xs={12}>
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('Description')}
            </Typography>
            <ExpandableMarkdown source={data.description} limit={300} />
          </Grid>
          <Grid item xs={12}>
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('Coverage information')}
            </Typography>
            <Paper elevation={2} style={{ padding: 20, marginTop: 10, backgroundColor: 'rgba(255, 255, 255, 0.02)' }}>
              <SecurityCoverageInformation coverage_information={data.coverage_information ?? []}/>
            </Paper>
          </Grid>
          <Grid item xs={12}>
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('Object covered')}
            </Typography>
            {data.objectCovered ? (
              <div className={classes.coveredObject}>
                <Button
                  size="small"
                  startIcon={<ItemIcon type={data.objectCovered.entity_type} />}
                  component={Link}
                  to={`/dashboard/id/${data.objectCovered.id}`}
                >
                  {data.objectCovered.representative?.main}
                </Button>
              </div>
            ) : (
              '-'
            )}
          </Grid>
          <Grid item xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('Last result')}
            </Typography>
            {data.coverage_last_result ? fd(data.coverage_last_result) : '-'}
          </Grid>
          <Grid item xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('Valid from')}
            </Typography>
            {data.coverage_valid_from ? fd(data.coverage_valid_from) : '-'}
          </Grid>
          <Grid item xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('Valid until')}
            </Typography>
            {data.coverage_valid_to ? fd(data.coverage_valid_to) : '-'}
          </Grid>
          <Grid item xs={6}>
            <SecurityCoverageSecurityPlatforms securityCoverage={data} />
          </Grid>
          <Grid item xs={6}>
            <SecurityCoverageVulnerabilities securityCoverage={data} />
          </Grid>
        </Grid>
      </Paper>
    </div>
  );
};

export default SecurityCoverageDetails;
