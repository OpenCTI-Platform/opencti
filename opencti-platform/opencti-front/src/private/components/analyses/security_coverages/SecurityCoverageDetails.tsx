import React, { FunctionComponent, useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import makeStyles from '@mui/styles/makeStyles';
import Grid from '@mui/material/Grid';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListItemButton from '@mui/material/ListItemButton';
import { Theme } from '@mui/material/styles/createTheme';
import SecurityCoverageInformation from '@components/analyses/security_coverages/SecurityCoverageInformation';
import { Link } from 'react-router-dom';
import Button from '@common/button/Button';
import { useTheme } from '@mui/styles';
import { useFormatter } from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import { SecurityCoverageDetails_securityCoverage$key } from './__generated__/SecurityCoverageDetails_securityCoverage.graphql';
import SecurityCoverageSecurityPlatforms from './SecurityCoverageSecurityPlatforms';
import SecurityCoverageVulnerabilities from './SecurityCoverageVulnerabilities';
import { isNotEmptyField } from '../../../../utils/utils';
import { fileUri } from '../../../../relay/environment';
import obasDark from '../../../../static/images/xtm/obas_dark.png';
import obasLight from '../../../../static/images/xtm/obas_light.png';
import ExternalLinkPopover from '../../../../components/ExternalLinkPopover';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  paper: {
    marginTop: theme.spacing(1),
    padding: '15px',
    borderRadius: 4,
    position: 'relative',
    display: 'flex',
    flexFlow: 'column',
  },
}));

const securityCoverageDetailsFragment = graphql`
  fragment SecurityCoverageDetails_securityCoverage on SecurityCoverage {
    id
    name
    description
    external_uri
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
  const theme = useTheme<Theme>();
  const { t_i18n, fndt } = useFormatter();
  const data = useFragment(securityCoverageDetailsFragment, securityCoverage);

  const [displayExternalLink, setDisplayExternalLink] = useState(false);

  return (
    <div style={{ height: '100%' }}>
      <Typography variant="h4" gutterBottom={true}>
        {t_i18n('Entity details')}
      </Typography>
      <Paper classes={{ root: classes.paper }} className="paper-for-grid" variant="outlined">
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
            {isNotEmptyField(data.external_uri) && (
              <Button
                startIcon={(
                  <img
                    style={{ width: 20 }}
                    src={fileUri(theme.palette.mode === 'dark' ? obasDark : obasLight)}
                    alt="OBAS"
                  />
                )}
                variant="secondary"
                onClick={() => setDisplayExternalLink(true)}
                title={data.external_uri} // tooltip on hover
              >
                {t_i18n('Exposure validation')}
              </Button>
            )}
            <Paper variant="outlined" style={{ padding: 20, marginTop: 10 }}>
              <SecurityCoverageInformation coverage_information={data.coverage_information ?? []} variant="details" />
            </Paper>
          </Grid>
          <Grid item xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('Last result')}
            </Typography>
            {data.coverage_last_result ? fndt(data.coverage_last_result) : '-'}
          </Grid>
          <Grid item xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('Covered entity')}
            </Typography>
            <List style={{ marginTop: -10 }}>
              <FieldOrEmpty source={data.objectCovered}>
                {data.objectCovered && (
                  <ListItem
                    dense={true}
                    divider={true}
                    disablePadding={true}
                  >
                    <ListItemButton
                      component={Link}
                      to={`/dashboard/id/${data.objectCovered.id}`}
                    >
                      <ListItemIcon>
                        <ItemIcon type={data.objectCovered.entity_type} />
                      </ListItemIcon>
                      <ListItemText primary={data.objectCovered.representative?.main} />
                    </ListItemButton>
                  </ListItem>
                )}
              </FieldOrEmpty>
            </List>
          </Grid>
          <Grid item xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('Valid from')}
            </Typography>
            {data.coverage_valid_from ? fndt(data.coverage_valid_from) : '-'}
          </Grid>
          <Grid item xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('Valid until')}
            </Typography>
            {data.coverage_valid_to ? fndt(data.coverage_valid_to) : '-'}
          </Grid>
          <Grid item xs={12}>
            <SecurityCoverageSecurityPlatforms securityCoverage={data} />
          </Grid>
          <Grid item xs={12}>
            <SecurityCoverageVulnerabilities securityCoverage={data} />
          </Grid>
        </Grid>
      </Paper>

      {isNotEmptyField(data.external_uri) && (
        <ExternalLinkPopover
          externalLink={data.external_uri}
          displayExternalLink={displayExternalLink}
          setDisplayExternalLink={setDisplayExternalLink}
        />
      )}
    </div>
  );
};

export default SecurityCoverageDetails;
