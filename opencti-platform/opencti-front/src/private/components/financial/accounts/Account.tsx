import { makeStyles } from '@mui/styles';
import { graphql, useFragment } from 'react-relay';
import { Grid } from '@mui/material';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import { Account_financialAccount$key } from './__generated__/Account_financialAccount.graphql';
import AccountPopover from './AccountPopover';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import AccountDetails from './AccountDetails';
import SimpleStixObjectOrStixRelationshipStixCoreRelationships from '../../common/stix_core_relationships/SimpleStixObjectOrStixRelationshipStixCoreRelationships';
import StixCoreObjectExternalReferences from '../../analyses/external_references/StixCoreObjectExternalReferences';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import StixCoreObjectOrStixCoreRelationshipNotes from '../../analyses/notes/StixCoreObjectOrStixCoreRelationshipNotes';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import AccountEdition from './AccountEdition';
import Security from '../../../../utils/Security';
import StixCoreObjectOrStixRelationshipLastContainers from '../../common/containers/StixCoreObjectOrStixRelationshipLastContainers';

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
}));

const accountFragment = graphql`
  fragment Account_financialAccount on FinancialAccount {
    id
    standard_id
    spec_version
    revoked
    created
    modified
    created_at
    updated_at
    createdBy {
      ... on Identity {
        id
        name
        entity_type
      }
    }
    creators {
      id
      name
    }
    objectMarking {
      edges {
        node {
          id
          definition_type
          definition
          x_opencti_order
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
    currency_code
    name
    financial_account_number
    financial_account_status
    financial_account_type
    financial_account_balances {
      as_of_date
      balance
    }
    international_bank_account_number
  }
`;

const AccountComponent = ({
  accountData,
}: {
  accountData: Account_financialAccount$key;
}) => {
  const classes = useStyles();
  const account = useFragment<Account_financialAccount$key>(
    accountFragment,
    accountData,
  );
  return (
    <div className={classes.container}>
      <StixDomainObjectHeader
        entityType={'Financial-Account'}
        disableSharing={true}
        stixDomainObject={account}
        isOpenctiAlias={false}
        PopoverComponent={<AccountPopover id={account.id} />}
      />
      <Grid
        container={true}
        spacing={3}
        classes={{ container: classes.gridContainer }}
      >
        <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
          <AccountDetails account={account} />
        </Grid>
        <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
          <StixDomainObjectOverview stixDomainObject={account} />
        </Grid>
      </Grid>
      <Grid
        container={true}
        spacing={3}
        classes={{ container: classes.gridContainer }}
        style={{ marginTop: 25 }}
      >
        <Grid item={true} xs={6}>
          <SimpleStixObjectOrStixRelationshipStixCoreRelationships
            stixObjectOrStixRelationshipId={account.id}
            stixObjectOrStixRelationshipLink={`/dashboard/financial/accounts/${account.id}/knowledge`}
          />
        </Grid>
        <Grid item={true} xs={6}>
          <StixCoreObjectOrStixRelationshipLastContainers
            authorId={account.id}
          />
        </Grid>
      </Grid>
      <Grid
        container={true}
        spacing={3}
        classes={{ container: classes.gridContainer }}
        style={{ marginTop: 25 }}
      >
        <Grid item={true} xs={6}>
          <StixCoreObjectExternalReferences
            stixCoreObjectId={account.id}
          />
        </Grid>
        <Grid item={true} xs={6}>
          <StixCoreObjectLatestHistory
            stixCoreObjectId={account.id}
          />
        </Grid>
      </Grid>
      <StixCoreObjectOrStixCoreRelationshipNotes
        stixCoreObjectOrStixCoreRelationshipId={account.id}
        defaultMarkings={(account.objectMarking?.edges ?? []).map((edge) => edge.node)}
      />
      <Security needs={[KNOWLEDGE_KNUPDATE]}>
        <AccountEdition accountId={account.id} />
      </Security>
    </div>
  );
};

export default AccountComponent;
