import React, { useState } from 'react';
import { dissoc, filter, includes, map, pipe, toPairs } from 'ramda';
import { createFragmentContainer, graphql } from 'react-relay';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import { GetAppOutlined } from '@mui/icons-material';
import Button from '@mui/material/Button';
import Divider from '@mui/material/Divider';
import makeStyles from '@mui/styles/makeStyles';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import { useFormatter } from '../../../../components/i18n';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import { APP_BASE_PATH } from '../../../../relay/environment';
import StixCyberObservableIndicators from './StixCyberObservableIndicators';
import ItemOpenVocab from '../../../../components/ItemOpenVocab';
import ItemCopy from '../../../../components/ItemCopy';
import useVocabularyCategory from '../../../../utils/hooks/useVocabularyCategory';
import StixCyberObservableMalwareAnalyses from './StixCyberObservableMalwareAnalyses';
import useAttributes from '../../../../utils/hooks/useAttributes';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles((theme) => ({
  paper: {
    marginTop: theme.spacing(1),
    padding: '15px',
    borderRadius: 4,
  },
}));

const StixCyberObservableDetailsComponent = ({ stixCyberObservable }) => {
  const classes = useStyles();
  const { t_i18n, b, fldt } = useFormatter();
  const { isVocabularyField, fieldToCategory } = useVocabularyCategory();
  const { dateAttributes, ignoredAttributes } = useAttributes();
  const [anchorEl, setAnchorEl] = useState(null);
  const handleOpen = (event) => {
    setAnchorEl(event.currentTarget);
  };
  const handleClose = () => {
    setAnchorEl(null);
  };
  const handleLink = (url) => {
    handleClose();
    window.location.pathname = url;
  };
  const observableAttributes = pipe(
    dissoc('id'),
    dissoc('entity_type'),
    dissoc('obsContent'),
    toPairs,
    map((n) => ({ key: n[0], value: n[1] })),
    filter(
      (n) => n.value
        && !includes(n.key, ignoredAttributes)
        && !n.key.startsWith('__'),
    ),
  )(stixCyberObservable);
  const file = stixCyberObservable.importFiles
    && stixCyberObservable.importFiles.edges.length > 0
    ? stixCyberObservable.importFiles.edges[0].node
    : null;
  const isObservableAnalysable = [
    'StixFile',
    'Domain-Name',
    'Url',
    'Hostname',
    'Artifact',
    'Network-Traffic',
  ].includes(stixCyberObservable.entity_type);
  const encodedFilePath = file && encodeURIComponent(file.id);
  return (
    <div style={{ height: '100%' }} className="break">
      <Typography variant="h4" gutterBottom={true}>
        {t_i18n('Details')}
      </Typography>
      <Paper classes={{ root: classes.paper }} className={'paper-for-grid'} variant="outlined">
        <Grid container={true} spacing={3} style={{ marginBottom: 10 }}>
          {file && (
            <Grid item xs={6}>
              <Typography variant="h3" gutterBottom={true}>
                {t_i18n('File')}
              </Typography>
              <Button
                variant="outlined"
                color="secondary"
                size="small"
                startIcon={<GetAppOutlined />}
                onClick={handleOpen}
              >
                {t_i18n('Download')} ({b(file.size)})
              </Button>
              <Menu
                anchorEl={anchorEl}
                open={Boolean(anchorEl)}
                onClose={handleClose}
              >
                <MenuItem
                  dense={true}
                  onClick={() => handleLink(
                    `${APP_BASE_PATH}/storage/encrypted/${encodedFilePath}`,
                  )
                  }
                >
                  {t_i18n('Encrypted archive')}
                </MenuItem>
                <MenuItem
                  dense={true}
                  onClick={() => handleLink(
                    `${APP_BASE_PATH}/storage/get/${encodedFilePath}`,
                  )
                  }
                >
                  {t_i18n('Raw file')}
                </MenuItem>
              </Menu>
            </Grid>
          )}
          <Grid item xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('Description')}
            </Typography>
            <ExpandableMarkdown
              source={stixCyberObservable.x_opencti_description}
              limit={400}
            />
          </Grid>
          {observableAttributes.map((observableAttribute) => {
            if (observableAttribute.key === 'hashes') {
              return observableAttribute.value.map((hash) => (
                <Grid key={hash.algorithm} item xs={6}>
                  <Typography variant="h3" gutterBottom={true}>
                    {hash.algorithm} - hashes
                  </Typography>
                  <pre>
                    <ItemCopy content={hash.hash} />
                  </pre>
                </Grid>
              ));
            }
            if (observableAttribute.key === 'startup_info') {
              return observableAttribute.value.map((hash) => (
                <Grid key={hash.key} item xs={6}>
                  <Typography variant="h3" gutterBottom={true}>
                    {hash.key} - startup_info
                  </Typography>
                  <pre>
                    <ItemCopy content={hash.value} />
                  </pre>
                </Grid>
              ));
            }
            if (
              isVocabularyField(
                stixCyberObservable.entity_type,
                observableAttribute.key,
              )
            ) {
              return (
                <Grid key={observableAttribute.key} item xs={6}>
                  <Typography variant="h3" gutterBottom={true}>
                    {t_i18n(observableAttribute.key)}
                  </Typography>
                  <ItemOpenVocab
                    small={false}
                    type={fieldToCategory(
                      stixCyberObservable.entity_type,
                      observableAttribute.key,
                    )}
                    value={observableAttribute.value}
                  />
                </Grid>
              );
            }
            let finalValue = observableAttribute.value;
            if (includes(observableAttribute.key, dateAttributes)) {
              finalValue = fldt(finalValue);
            }
            if (finalValue === true) {
              finalValue = 'TRUE';
            } else if (finalValue === false) {
              finalValue = 'FALSE';
            }
            if (Array.isArray(finalValue)) {
              finalValue = finalValue.join('\n');
            }
            return (
              <Grid key={observableAttribute.key} item xs={6}>
                <Typography variant="h3" gutterBottom={true}>
                  {t_i18n(observableAttribute.key.replace('attribute_', ''))}
                </Typography>
                <pre>
                  <ItemCopy content={finalValue || '-'} />
                </pre>
              </Grid>
            );
          })}
        </Grid>
        <Divider />
        <StixCyberObservableIndicators
          stixCyberObservable={stixCyberObservable}
        />
        {isObservableAnalysable && (
          <StixCyberObservableMalwareAnalyses
            observableId={stixCyberObservable.id}
          />
        )}
      </Paper>
    </div>
  );
};

const StixCyberObservableDetails = createFragmentContainer(
  StixCyberObservableDetailsComponent,
  {
    stixCyberObservable: graphql`
      fragment StixCyberObservableDetails_stixCyberObservable on StixCyberObservable {
        id
        entity_type
        x_opencti_score
        x_opencti_description
        observable_value
        ... on AutonomousSystem {
          number
          observableName: name
          rir
        }
        ... on Directory {
          path
          path_enc
          ctime
          mtime
          atime
        }
        ... on DomainName {
          value
        }
        ... on EmailAddr {
          value
          display_name
        }
        ... on EmailMessage {
          is_multipart
          attribute_date
          content_type
          message_id
          subject
          received_lines
          body
        }
        ... on Artifact {
          x_opencti_additional_names
          mime_type
          payload_bin
          url
          encryption_algorithm
          decryption_key
          hashes {
            algorithm
            hash
          }
          importFiles(first: 500) {
            edges {
              node {
                id
                name
                size
                metaData {
                  mimetype
                }
              }
            }
          }
        }
        ... on StixFile {
          extensions
          size
          observableName: name
          name_enc
          magic_number_hex
          mime_type
          ctime
          mtime
          atime
          x_opencti_additional_names
          obsContent {
            id
          }
          hashes {
            algorithm
            hash
          }
        }
        ... on X509Certificate {
          is_self_signed
          version
          serial_number
          signature_algorithm
          issuer
          subject
          subject_public_key_algorithm
          subject_public_key_modulus
          subject_public_key_exponent
          validity_not_before
          validity_not_after
          hashes {
            algorithm
            hash
          }
          basic_constraints
          name_constraints
          policy_constraints
          key_usage
          extended_key_usage
          subject_key_identifier
          authority_key_identifier
          subject_alternative_name
          issuer_alternative_name
          subject_directory_attributes
          crl_distribution_points
          inhibit_any_policy
          private_key_usage_period_not_before
          private_key_usage_period_not_after
          certificate_policies
          policy_mappings
        }
        ... on IPv4Addr {
          value
        }
        ... on IPv6Addr {
          value
        }
        ... on MacAddr {
          value
        }
        ... on Mutex {
          observableName: name
        }
        ... on NetworkTraffic {
          extensions
          start
          end
          is_active
          src_port
          dst_port
          protocols
          src_byte_count
          dst_byte_count
          src_packets
          dst_packets
        }
        ... on Process {
          extensions
          is_hidden
          pid
          created_time
          cwd
          command_line
          environment_variables
          ## windows-process-ext
          aslr_enabled
          dep_enabled
          priority
          owner_sid
          window_title
          startup_info {
            key
            value
          }
          integrity_level
          ## windows-service-ext
          service_name
          descriptions
          display_name
          group_name
          start_type
          service_type
          service_status
        }
        ... on Software {
          observableName: name
          cpe
          swid
          languages
          vendor
          version
        }
        ... on Url {
          value
        }
        ... on UserAccount {
          extensions
          user_id
          credential
          account_login
          account_type
          display_name
          is_service_account
          is_privileged
          can_escalate_privs
          is_disabled
          account_created
          account_expires
          credential_last_changed
          account_first_login
          account_last_login
        }
        ... on WindowsRegistryKey {
          attribute_key
          modified_time
          number_of_subkeys
        }
        ... on WindowsRegistryValueType {
          observableName: name
          data
          data_type
        }
        ... on Hostname {
          value
        }
        ... on CryptographicKey {
          value
        }
        ... on CryptocurrencyWallet {
          value
        }
        ... on Text {
          value
        }
        ... on UserAgent {
          value
        }
        ... on BankAccount {
          iban
          bic
          account_number
        }
        ... on Credential {
          value
        }
        ... on TrackingNumber {
          value
        }
        ... on PhoneNumber {
          value
        }
        ... on PaymentCard {
          card_number
          expiration_date
          cvv
          holder_name
        }
        ... on MediaContent {
          title
          content
          media_category
          url
          publication_date
        }
        ... on Persona {
          persona_name
          persona_type
        }
        ...StixCyberObservableIndicators_stixCyberObservable
      }
    `,
  },
);

export default StixCyberObservableDetails;
