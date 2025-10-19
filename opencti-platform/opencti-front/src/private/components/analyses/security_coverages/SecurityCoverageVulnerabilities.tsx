import React, { FunctionComponent } from 'react';
import Typography from '@mui/material/Typography';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { Link } from 'react-router-dom';
import IconButton from '@mui/material/IconButton';
import { LinkOff } from '@mui/icons-material';
import { Bug } from 'mdi-material-ui';
import { createFragmentContainer, graphql } from 'react-relay';
import { ListItemButton } from '@mui/material';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { commitMutation } from '../../../../relay/environment';
import { deleteNodeFromEdge } from '../../../../utils/store';
import { useFormatter } from '../../../../components/i18n';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import AddVulnerabilities from './AddVulnerabilities';
import { SecurityCoverageVulnerabilities_securityCoverage$data } from './__generated__/SecurityCoverageVulnerabilities_securityCoverage.graphql';

const removeMutation = graphql`
  mutation SecurityCoverageVulnerabilitiesRelationDeleteMutation(
    $fromId: StixRef!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    stixCoreRelationshipDelete(
      fromId: $fromId
      toId: $toId
      relationship_type: $relationship_type
    )
  }
`;

interface SecurityCoverageVulnerabilitiesProps {
  securityCoverage: SecurityCoverageVulnerabilities_securityCoverage$data;
}

const SecurityCoverageVulnerabilitiesComponent: FunctionComponent<SecurityCoverageVulnerabilitiesProps> = ({
  securityCoverage,
}) => {
  const { t_i18n } = useFormatter();

  const removeVulnerability = (vulnerabilityEdge: {
    node: {
      id: string;
      to: {
        id?: string;
      } | null | undefined;
    };
  }) => {
    if (!vulnerabilityEdge.node.to?.id) return;
    commitMutation({
      mutation: removeMutation,
      variables: {
        fromId: securityCoverage.id,
        toId: vulnerabilityEdge.node.to.id,
        relationship_type: 'has-covered',
      },
      updater: (store: RecordSourceSelectorProxy) => {
        deleteNodeFromEdge(
          store,
          'vulnerabilities',
          securityCoverage.id,
          vulnerabilityEdge.node.id,
          {
            relationship_type: 'has-covered',
            toTypes: ['Vulnerability'],
          },
        );
      },
      optimisticUpdater: undefined,
      optimisticResponse: undefined,
      onCompleted: undefined,
      onError: undefined,
      setSubmitting: undefined,
    });
  };

  return (
    <div style={{ marginTop: 20 }}>
      <div style={{ display: 'flex', flexDirection: 'row' }}>
        <Typography variant="h3" gutterBottom={true}>
          {t_i18n('Vulnerabilities')}
        </Typography>
        <AddVulnerabilities
          securityCoverage={securityCoverage}
          securityCoverageVulnerabilities={securityCoverage.vulnerabilities?.edges || []}
        />
      </div>
      <div className="clearfix" />
      <List style={{ marginTop: -10 }}>
        <FieldOrEmpty source={securityCoverage.vulnerabilities?.edges}>
          {securityCoverage.vulnerabilities?.edges?.map((vulnerabilityEdge) => {
            const vulnerability = vulnerabilityEdge.node.to;
            return (
              <ListItem
                key={vulnerabilityEdge.node.id}
                dense={true}
                divider={true}
                disablePadding={true}
                secondaryAction={
                  <IconButton
                    aria-label="Remove"
                    onClick={() => removeVulnerability(vulnerabilityEdge)}
                    size="large"
                  >
                    <LinkOff/>
                  </IconButton>
                }
              >
                <ListItemButton
                  component={Link}
                  to={`/dashboard/arsenal/vulnerabilities/${vulnerability?.id}`}
                >
                  <ListItemIcon>
                    <Bug color="primary"/>
                  </ListItemIcon>
                  <ListItemText primary={vulnerability?.name}/>
                </ListItemButton>
              </ListItem>
            );
          })}
        </FieldOrEmpty>
      </List>
    </div>
  );
};

const SecurityCoverageVulnerabilities = createFragmentContainer(
  SecurityCoverageVulnerabilitiesComponent,
  {
    securityCoverage: graphql`
      fragment SecurityCoverageVulnerabilities_securityCoverage on SecurityCoverage {
        id
        name
        parent_types
        entity_type
        vulnerabilities: stixCoreRelationships(
          relationship_type: "has-covered"
          toTypes: ["Vulnerability"]
          first: 200
        ) @connection(key: "Pagination_vulnerabilities") {
          edges {
            node {
              id
              to {
                ... on Vulnerability {
                  id
                  parent_types
                  name
                  description
                }
              }
            }
          }
        }
      }
    `,
  },
);

export default SecurityCoverageVulnerabilities;
