import React, { FunctionComponent, useState } from 'react';
import Button from '@mui/material/Button';
import { Link } from 'react-router-dom';
import Tooltip from '@mui/material/Tooltip';
import makeStyles from '@mui/styles/makeStyles';
import { useTheme } from '@mui/styles';
import { Theme } from '@mui/material/styles/createTheme';
import type { Theme as ComponentTheme } from '../../../../components/Theme';
import SecurityCoverageInformation from '../../analyses/security_coverages/SecurityCoverageInformation';
import Drawer from '../drawer/Drawer';
import { fileUri } from '../../../../relay/environment';
import obasLight from '../../../../static/images/xtm/obas_light.png';
import obasDark from '../../../../static/images/xtm/obas_dark.png';
import { useFormatter } from '../../../../components/i18n';
import useGranted, { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import { isEmptyField } from '../../../../utils/utils';
import { SecurityCoverageCreationForm } from '../../analyses/security_coverages/SecurityCoverageCreation';
import { QueryRenderer } from '../../../../relay/environment';
import { graphql } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import Loader, { LoaderVariant } from '../../../../components/Loader';

// GraphQL fragment to be included in STIX Core Object queries
export const StixCoreObjectSecurityCoverageFragment = graphql`
  fragment StixCoreObjectSecurityCoverage_stixCoreObject on StixCoreObject {
    securityCoverage {
      id
      coverage_information {
        coverage_name
        coverage_score
      }
    }
  }
`;

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  simulationResults: {
    display: 'flex',
    alignItems: 'center',
    gap: 10,
  },
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
}));

interface SecurityCoverage {
  id: string;
  coverage_information: ReadonlyArray<{
    readonly coverage_name: string;
    readonly coverage_score: number;
  }> | null;
}

interface StixCoreObjectSecurityCoverageProps {
  id: string; // ID of the STIX Core Object
  coverage?: SecurityCoverage | null;
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

interface ConnectorsQueryProps {
  connectors?: Array<{
    active: boolean;
    connector_type?: string;
    connector_scope?: string[];
  }>;
}

const StixCoreObjectSecurityCoverage: FunctionComponent<StixCoreObjectSecurityCoverageProps> = ({ 
  id, 
  coverage,
  onCoverageCreated
}) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  const theme = useTheme<ComponentTheme>();
  const isGrantedToUpdate = useGranted([KNOWLEDGE_KNUPDATE]);
  
  const [open, setOpen] = useState(false);

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
    if (newCoverage && onCoverageCreated) {
      const coverageId = newCoverage.getValue('id');
      if (typeof coverageId === 'string') {
        onCoverageCreated(coverageId);
      }
    }
  };

  return (
    <>
      <div className={classes.simulationResults}>
        {isEmptyField(coverage) && (
          <Tooltip title={t_i18n('Create a coverage')}>
            <Button
              variant="outlined"
              size="small"
              style={{ fontSize: 12 }}
              disabled={!isGrantedToUpdate}
              onClick={handleOpen}
            >
              <img 
                style={{ width: 20, height: 20, marginRight: 5, display: 'block' }} 
                src={fileUri(theme.palette.mode === 'dark' ? obasDark : obasLight)} 
                alt="OAEV" 
              />
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
              />
            );
          }}
        />
      </Drawer>
    </>
  );
};

export default StixCoreObjectSecurityCoverage;
