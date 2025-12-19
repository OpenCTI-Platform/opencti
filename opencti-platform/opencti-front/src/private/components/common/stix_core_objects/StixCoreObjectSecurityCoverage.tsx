import React, { FunctionComponent, useState, useEffect } from 'react';
import Button from '@common/button/Button';
import { Link } from 'react-router-dom';
import Tooltip from '@mui/material/Tooltip';
import makeStyles from '@mui/styles/makeStyles';
import { Theme } from '@mui/material/styles/createTheme';
import { graphql } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { ShieldCheckOutline } from 'mdi-material-ui';
import SecurityCoverageInformation from '../../analyses/security_coverages/SecurityCoverageInformation';
import Drawer from '../drawer/Drawer';
import { QueryRenderer } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import useGranted, { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import { isEmptyField } from '../../../../utils/utils';
import { SecurityCoverageCreationForm } from '../../analyses/security_coverages/SecurityCoverageCreation';
import Loader, { LoaderVariant } from '../../../../components/Loader';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>(() => ({
  simulationResults: {
    display: 'flex',
    alignItems: 'center',
    gap: 10,
  },
}));

interface SecurityCoverage {
  id: string;
  coverage_information: ReadonlyArray<{
    readonly coverage_name: string;
    readonly coverage_score: number;
  }> | null | undefined;
}

interface StixCoreObjectSecurityCoverageProps {
  id: string; // ID of the STIX Core Object
  coverage?: SecurityCoverage | null | undefined;
  onCoverageCreated?: (coverageId: string) => void;
}

// Query for checking enrichment connectors availability
const securityCoverageConnectorsQuery = graphql`
  query StixCoreObjectSecurityCoverageConnectorsQuery {
    connectors {
      id
      name
      active
      connector_type
      connector_scope
    }
  }
`;

// Query for fetching entity representative
const securityCoverageEntityQuery = graphql`
  query StixCoreObjectSecurityCoverageEntityQuery($id: String!) {
    stixCoreObject(id: $id) {
      id
      entity_type
      representative {
        main
      }
    }
  }
`;

interface ConnectorsQueryProps {
  connectors?: Array<{
    active: boolean;
    connector_type?: string;
    connector_scope?: string[];
  }>;
}

const StixCoreObjectSecurityCoverage: FunctionComponent<StixCoreObjectSecurityCoverageProps> = ({
  id,
  coverage: initialCoverage,
  onCoverageCreated,
}) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  const isGrantedToUpdate = useGranted([KNOWLEDGE_KNUPDATE]);

  const [open, setOpen] = useState(false);
  const [coverage, setCoverage] = useState(initialCoverage);

  // Update local state when prop changes
  useEffect(() => {
    setCoverage(initialCoverage);
  }, [initialCoverage]);

  const handleClose = () => {
    setOpen(false);
  };

  const handleOpen = () => {
    setOpen(true);
  };

  const updater = (store: RecordSourceSelectorProxy, key: string) => {
    // Custom updater logic for handling the security coverage creation
    // This will be called after successful creation
    const newCoverage = store.getRootField(key);
    if (newCoverage) {
      const coverageId = newCoverage.getValue('id');
      if (typeof coverageId === 'string') {
        // Update local state to show the new coverage
        const coverageInformation = newCoverage.getLinkedRecords('coverage_information');
        const informationArray = coverageInformation ? coverageInformation.map((info) => ({
          coverage_name: info?.getValue('coverage_name') as string,
          coverage_score: info?.getValue('coverage_score') as number,
        })) : [];

        setCoverage({
          id: coverageId,
          coverage_information: informationArray,
        });

        // Close the drawer
        handleClose();

        // Call the callback if provided
        if (onCoverageCreated) {
          onCoverageCreated(coverageId);
        }
      }
    }
  };

  return (
    <>
      <div className={classes.simulationResults}>
        {isEmptyField(coverage) && (
          <Tooltip title={t_i18n('Create a coverage')}>
            <Button
              variant="secondary"
              size="small"
              style={{ fontSize: 12 }}
              disabled={!isGrantedToUpdate}
              onClick={handleOpen}
              startIcon={<ShieldCheckOutline />}
            >
              {t_i18n('Add Security coverage')}
            </Button>
          </Tooltip>
        )}
        {coverage && (
          <Button
            size="small"
            component={Link}
            to={`/dashboard/analyses/security_coverages/${coverage.id}`}
          >
            <SecurityCoverageInformation coverage_information={coverage?.coverage_information} />
          </Button>
        )}
      </div>
      <Drawer
        title={t_i18n('Create a security coverage')}
        open={open}
        onClose={handleClose}
      >
        <QueryRenderer
          query={securityCoverageEntityQuery}
          variables={{ id }}
          render={({ props: entityProps }: { props: { stixCoreObject: { id: string; entity_type: string; representative?: { main?: string } } } | null }) => {
            if (!entityProps) {
              return <Loader variant={LoaderVariant.inElement} />;
            }
            const entityName = entityProps?.stixCoreObject?.representative?.main;
            return (
              <QueryRenderer
                query={securityCoverageConnectorsQuery}
                variables={{}}
                render={({ props }: { props: ConnectorsQueryProps | null }) => {
                  if (!props) {
                    return <Loader variant={LoaderVariant.inElement} />;
                  }

                  const connectors = props?.connectors || [];
                  const hasConnector = connectors.some((connector) => {
                    return connector.active
                      && connector.connector_type === 'INTERNAL_ENRICHMENT'
                      && connector.connector_scope
                      && connector.connector_scope.some((scope: string) => scope.toLowerCase() === 'security-coverage');
                  });

                  return (
                    <SecurityCoverageCreationForm
                      updater={updater}
                      onClose={handleClose}
                      hasEnrichmentConnectors={hasConnector}
                      preSelectedEntityId={id}
                      preSelectedEntityName={entityName}
                    />
                  );
                }}
              />
            );
          }}
        />
      </Drawer>
    </>
  );
};

export default StixCoreObjectSecurityCoverage;
