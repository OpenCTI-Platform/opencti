import React, { FunctionComponent, useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import Grid from '@mui/material/Grid';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListItemButton from '@mui/material/ListItemButton';
import SecurityCoverageInformation from '@components/analyses/security_coverages/SecurityCoverageInformation';
import { Link } from 'react-router-dom';
import { useFormatter } from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import { SecurityCoverageDetails_securityCoverage$key } from './__generated__/SecurityCoverageDetails_securityCoverage.graphql';
import SecurityCoverageSecurityPlatforms from './SecurityCoverageSecurityPlatforms';
import SecurityCoverageVulnerabilities from './SecurityCoverageVulnerabilities';
import { isNotEmptyField } from '../../../../utils/utils';
import ExternalLinkPopover from '../../../../components/ExternalLinkPopover';
import Card from '../../../../components/common/card/Card';
import Label from '../../../../components/common/label/Label';
import { EMPTY_VALUE } from '../../../../utils/String';

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
  const { t_i18n, fndt } = useFormatter();
  const data = useFragment(securityCoverageDetailsFragment, securityCoverage);
  const [displayExternalLink, setDisplayExternalLink] = useState(false);

  return (
    <div style={{ height: '100%' }}>
      <Card title={t_i18n('Entity details')}>
        <Grid container={true} spacing={2}>
          <Grid item xs={12}>
            <Label>
              {t_i18n('Name')}
            </Label>
            {data.name || EMPTY_VALUE}
          </Grid>
          <Grid item xs={12}>
            <Label>
              {t_i18n('Description')}
            </Label>
            <ExpandableMarkdown source={data.description} limit={300} />
          </Grid>
          <Grid item xs={12}>
            <Label sx={{ marginBottom: '8px' }}>
              {t_i18n('Coverage information')}
            </Label>
            <SecurityCoverageInformation coverage_information={data.coverage_information ?? []} variant="details" />
          </Grid>
          <Grid item xs={6}>
            <Label>
              {t_i18n('Last result')}
            </Label>
            {data.coverage_last_result ? fndt(data.coverage_last_result) : EMPTY_VALUE}
          </Grid>
          <Grid item xs={6}>
            <Label>
              {t_i18n('Covered entity')}
            </Label>
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
            <Label>
              {t_i18n('Valid from')}
            </Label>
            {data.coverage_valid_from ? fndt(data.coverage_valid_from) : EMPTY_VALUE}
          </Grid>
          <Grid item xs={6}>
            <Label>
              {t_i18n('Valid until')}
            </Label>
            {data.coverage_valid_to ? fndt(data.coverage_valid_to) : EMPTY_VALUE}
          </Grid>
          <Grid item xs={12}>
            <SecurityCoverageSecurityPlatforms securityCoverage={data} />
          </Grid>
          <Grid item xs={12}>
            <SecurityCoverageVulnerabilities securityCoverage={data} />
          </Grid>
        </Grid>
      </Card>

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
