import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import CaseDetails from './CaseDetails';
import { Case_case$key } from './__generated__/Case_case.graphql';
import CasePopover from './CasePopover';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import { CaseDetails_case$data } from './__generated__/CaseDetails_case.graphql';

const useStyles = makeStyles(() => ({
  gridContainer: {
    marginBottom: 20,
  },
  container: {
    margin: 0,
  },
}));

const caseFragment = graphql`
  fragment Case_case on Case {
    id
    standard_id
    x_opencti_stix_ids
    created
    modified
    created_at
    rating
    description
    createdBy {
      ... on Identity {
        id
        name
        entity_type
      }
    }
    creator {
      id
      name
    }
    objectMarking {
      edges {
        node {
          id
          definition
          x_opencti_color
        }
      }
    }
    objectLabel {
      edges {
        node {
          id
          value
          color
        }
      }
    }
    name
    x_opencti_stix_ids
    status {
      id
      order
      template {
        name
        color
      }
    }
    workflowEnabled
    ...CaseDetails_case
  }
`;

interface CaseProps {
  data: Case_case$key,
}

const CaseComponent:FunctionComponent<CaseProps> = ({ data }) => {
  const classes = useStyles();
  const caseData = useFragment(caseFragment, data);

  return (
    <div className={classes.container}>
      <StixDomainObjectHeader
        disableSharing={true}
        stixDomainObject={caseData}
        isOpenctiAlias={false}
        PopoverComponent={CasePopover}
      />
      <Grid
        container={true}
        spacing={3}
        classes={{ container: classes.gridContainer }}
      >
        <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
          <CaseDetails caseData={caseData}/>
        </Grid>
      </Grid>
      <Grid
        container={true}
        spacing={3}
        classes={{ container: classes.gridContainer }}
        style={{ marginTop: 25 }}
      >
      </Grid>
    </div>
  );
};

export default CaseComponent;
