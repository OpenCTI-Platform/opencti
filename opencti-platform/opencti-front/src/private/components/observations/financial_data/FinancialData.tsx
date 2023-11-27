/* eslint-disable @typescript-eslint/no-unused-vars */
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React from 'react';
import { dissoc, pipe } from 'ramda';
import { makeStyles } from '@mui/styles';
import { graphql, useFragment } from 'react-relay';
import { Theme } from 'src/components/Theme';
import { Grid } from '@mui/material';
import ErrorNotFound from 'src/components/ErrorNotFound';
import SimpleStixObjectOrStixRelationshipStixCoreRelationships from '@components/common/stix_core_relationships/SimpleStixObjectOrStixRelationshipStixCoreRelationships';
import StixCoreObjectLatestHistory from '@components/common/stix_core_objects/StixCoreObjectLatestHistory';
import StixCoreObjectOrStixRelationshipLastContainers from '@components/common/containers/StixCoreObjectOrStixRelationshipLastContainers';
import StixCoreObjectExternalReferences from '@components/analyses/external_references/StixCoreObjectExternalReferences';
import StixCoreObjectOrStixCoreRelationshipNotes from '@components/analyses/notes/StixCoreObjectOrStixCoreRelationshipNotes';
import { KNOWLEDGE_KNUPDATE } from 'src/utils/hooks/useGranted';
import Security from 'src/utils/Security';
import StixCyberObservableDetails from '../stix_cyber_observables/StixCyberObservableDetails';
import StixCyberObservableOverview from '../stix_cyber_observables/StixCyberObservableOverview';
import StixCyberObservableEdition from '../stix_cyber_observables/StixCyberObservableEdition';
import { FinancialData_financialAccount$data, FinancialData_financialAccount$key } from './__generated__/FinancialData_financialAccount.graphql';
import { FinancialData_financialAsset$data, FinancialData_financialAsset$key } from './__generated__/FinancialData_financialAsset.graphql';
import { FinancialData_financialTransaction$data, FinancialData_financialTransaction$key } from './__generated__/FinancialData_financialTransaction.graphql';

const useStyles = makeStyles<Theme>(() => ({
  gridContainer: {
    marginBottom: 20,
  },
}));

const financialAccountFragment = graphql`
  fragment FinancialData_financialAccount on FinancialAccount {
    id
    standard_id
    entity_type
    x_opencti_stix_ids
    spec_version
    created_at
    updated_at
    createdBy {
      ... on Identity {
        id
        name
        entity_type
        x_opencti_reliability
      }
    }
    creators {
      id
      name
    }
    objectMarking {
      id
      definition_type
      definition
      x_opencti_order
      x_opencti_color
    }
    objectLabel {
      id
      value
      color
    }
    account_number
    account_status
    account_type
    iban_number
    bic_number
    currency_code
  }
`;

const financialAssetFragment = graphql`
  fragment FinancialData_financialAsset on FinancialAsset {
    id
    standard_id
    entity_type
    x_opencti_stix_ids
    spec_version
    created_at
    updated_at
    createdBy {
      ... on Identity {
        id
        name
        entity_type
        x_opencti_reliability
      }
    }
    creators {
      id
      name
    }
    objectMarking {
      id
      definition_type
      definition
      x_opencti_order
      x_opencti_color
    }
    objectLabel {
      id
      value
      color
    }
    name
    asset_type
    asset_value
    currency_code
  }
`;

const financialTransactionFragment = graphql`
  fragment FinancialData_financialTransaction on FinancialTransaction {
    id
    standard_id
    entity_type
    x_opencti_stix_ids
    spec_version
    created_at
    updated_at
    createdBy {
      ... on Identity {
        id
        name
        entity_type
        x_opencti_reliability
      }
    }
    creators {
      id
      name
    }
    objectMarking {
      id
      definition_type
      definition
      x_opencti_order
      x_opencti_color
    }
    objectLabel {
      id
      value
      color
    }
    transaction_date
    transaction_value
    currency_code
  }
`;

const FinancialData = ({ data }: {
  data: FinancialData_financialAccount$data
  | FinancialData_financialAsset$data
  | FinancialData_financialTransaction$data,
}) => {
  const classes = useStyles();
  let financialDataFragment;
  switch (data.entity_type) {
    case 'Financial-Account':
      financialDataFragment = financialAccountFragment;
      break;
    case 'Financial-Asset':
      financialDataFragment = financialAssetFragment;
      break;
    case 'Financial-Transaction':
      financialDataFragment = financialTransactionFragment;
      break;
    default:
      return <ErrorNotFound />;
  }
  const financialData = useFragment<FinancialData_financialAccount$key
  | FinancialData_financialAsset$key
  | FinancialData_financialTransaction$key>(
    financialDataFragment,
    data,
  );
  const {
    creators,
    objectMarking,
    objectLabel,
    ...financialDataDetails
  } = financialData;

  const financialDataDetailsFiltered = pipe(
    // On Basic Information Tab, if record has rel_created-by.internal_id and not removed,
    // this will throw an error on render when ItemCopy is called in StixCyberObservableDetails
    // Some migrated records have this field from Cryptocurrency-Wallet or Bank-Account.
    dissoc('createdBy'),
  )(financialDataDetails);

  return (<>
    <Grid
      container={true}
      spacing={3}
      classes={{ container: classes.gridContainer }}
    >
      <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
        <StixCyberObservableDetails
          stixCyberObservable={financialDataDetailsFiltered}
        />
      </Grid>
      <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
        <StixCyberObservableOverview stixCyberObservable={financialData} />
      </Grid>
      <Grid item={true} xs={6} style={{ marginTop: 30 }}>
        <SimpleStixObjectOrStixRelationshipStixCoreRelationships
          stixObjectOrStixRelationshipId={financialData.id}
          stixObjectOrStixRelationshipLink={`/dashboard/observations/financial-data/${financialData.id}/knowledge`}
        />
      </Grid>
      <Grid item={true} xs={6} style={{ marginTop: 30 }}>
        <StixCoreObjectOrStixRelationshipLastContainers
          stixCoreObjectOrStixRelationshipId={financialData.id}
        />
      </Grid>
      <Grid item={true} xs={6} style={{ marginTop: 30 }}>
        <StixCoreObjectExternalReferences
          stixCoreObjectId={financialData.id}
        />
      </Grid>
      <Grid item={true} xs={6} style={{ marginTop: 30 }}>
        <StixCoreObjectLatestHistory
          stixCoreObjectId={financialData.id}
        />
      </Grid>
    </Grid>
    <StixCoreObjectOrStixCoreRelationshipNotes
      stixCoreObjectOrStixCoreRelationshipId={financialData.id}
      defaultMarkings={(financialData.objectMarking?.edges ?? []).map(
        (edge) => edge.node,
      )}
    />
    <Security needs={[KNOWLEDGE_KNUPDATE]}>
      <StixCyberObservableEdition
        stixCyberObservableId={financialData.id}
      />
    </Security>
  </>);
};

export default FinancialData;
