import React, { useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid2';
import { GetAppOutlined } from '@mui/icons-material';
import Button from '@mui/material/Button';
import Divider from '@mui/material/Divider';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import Box from '@mui/material/Box';
import { useTheme } from '@mui/styles';
import StixCyberObservableNestedEntities from './StixCyberObservableNestedEntities';
import { useFormatter } from '../../../../components/i18n';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import { APP_BASE_PATH } from '../../../../relay/environment';
import StixCyberObservableIndicators from './StixCyberObservableIndicators';
import ItemOpenVocab from '../../../../components/ItemOpenVocab';
import ItemCopy from '../../../../components/ItemCopy';
import useVocabularyCategory from '../../../../utils/hooks/useVocabularyCategory';
import StixCyberObservableMalwareAnalyses from './StixCyberObservableMalwareAnalyses';
import useAttributes from '../../../../utils/hooks/useAttributes';
import { StixCyberObservable_stixCyberObservable$data } from '@components/observations/stix_cyber_observables/__generated__/StixCyberObservable_stixCyberObservable.graphql';
import {
  StixCyberObservableDetails_stixCyberObservable$key,
} from '@components/observations/stix_cyber_observables/__generated__/StixCyberObservableDetails_stixCyberObservable.graphql';
import { Theme } from '../../../../components/Theme';
import { PopoverProps } from '@mui/material/Popover';
import useAttributeValueToReadableValue from '../../../../utils/hooks/useAttributeValueToReadableValue';

const stixCyberObservableDetailsFragment = graphql`
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
      x_opencti_product
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
    ... on SSHKey {
      key_type
      public_key
      fingerprint_sha256
      fingerprint_md5
      key_length
      expiration_date
      comment
      created
    }
    ...StixCyberObservableIndicators_stixCyberObservable
  }
`;

const reorderMediaContentObservablesAttributes = (data: { key: string; value: string }[]) => {
  const desiredOrder = ['content', 'title', 'media_category', 'url', 'publication_date'];

  return desiredOrder
    .map((key) => data.find((item) => item.key === key))
    .filter(Boolean) as { key: string; value: string }[];
};

interface DownloadFileButtonMenuProps {
  fileSize: number | null | undefined;
  encodedFilePath: string | null;
}

const DownloadFileButtonMenu = ({
  fileSize,
  encodedFilePath,
}: DownloadFileButtonMenuProps) => {
  const { t_i18n } = useFormatter();

  const [anchorEl, setAnchorEl] = useState<PopoverProps['anchorEl']>(null);

  const handleOpen = (event: React.SyntheticEvent) => {
    setAnchorEl(event.currentTarget);
  };

  const handleClose = () => {
    setAnchorEl(null);
  };

  const handleLink = (url: string) => {
    handleClose();
    window.location.pathname = url;
  };

  return (
    <>
      <Typography variant="h3" gutterBottom={true}>{t_i18n('File')}</Typography>

      <Button
        variant="outlined"
        color="secondary"
        size="small"
        startIcon={<GetAppOutlined />}
        onClick={handleOpen}
      >
        {t_i18n('Download')} ({(fileSize)})
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
          )}
        >
          {t_i18n('Encrypted archive')}
        </MenuItem>
        <MenuItem
          dense={true}
          onClick={() => handleLink(
            `${APP_BASE_PATH}/storage/get/${encodedFilePath}`,
          )}
        >
          {t_i18n('Raw file')}
        </MenuItem>
      </Menu>
    </>
  );
};

const LabelItemCopy = ({ label, value }: { label: string; value: string }) => {
  return (
    <>
      <Typography variant="h3" gutterBottom={true}>{label}</Typography>
      <pre>
        <ItemCopy content={value} />
      </pre>
    </>
  );
};

interface StixCyberObservableDetailsProps {
  data: StixCyberObservable_stixCyberObservable$data;
}

const StixCyberObservableDetails = ({ data }: StixCyberObservableDetailsProps) => {
  const theme = useTheme<Theme>();
  const stixCyberObservable = useFragment<StixCyberObservableDetails_stixCyberObservable$key>(stixCyberObservableDetailsFragment, data);

  const { t_i18n } = useFormatter();
  const { isVocabularyField, fieldToCategory } = useVocabularyCategory();
  const { ignoredAttributes } = useAttributes();

  const observableAttributes = Object.entries(stixCyberObservable)
    // remove unwanted keys
    .filter(([key, _]) =>
      key !== 'id'
      && key !== 'entity_type'
      && key !== 'obsContent',
    )
    .map(([key, value]) => ({ key, value }))
    // final filtering
    .filter((n) =>
      n.value
      && !ignoredAttributes.includes(n.key)
      && !n.key.startsWith('__'),
    );

  const file = stixCyberObservable.importFiles && stixCyberObservable.importFiles.edges.length > 0
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

  const orderedObservableAttributes = stixCyberObservable.entity_type === 'Media-Content'
    ? reorderMediaContentObservablesAttributes(observableAttributes)
    : observableAttributes;

  return (
    <div style={{ height: '100%' }} className="break">
      <Typography variant="h4" gutterBottom={true}>{t_i18n('Details')}</Typography>

      <Paper
        sx={{ padding: '15px', marginTop: theme.spacing(1) }}
        className="paper-for-grid"
        variant="outlined"
      >
        <Grid container={true} spacing={3} style={{ marginBottom: 10 }}>
          {file && (
            <Grid size={6}>
              <DownloadFileButtonMenu fileSize={file.size} encodedFilePath={encodedFilePath} />
            </Grid>
          )}

          <Grid size={6}>
            <>
              <Typography variant="h3" gutterBottom={true}>
                {t_i18n('Description')}
              </Typography>
              <ExpandableMarkdown
                source={stixCyberObservable.x_opencti_description}
                limit={400}
              />
            </>
          </Grid>

          {orderedObservableAttributes.map((observableAttribute) => {
            const { key, value } = observableAttribute;

            if (key === 'hashes') {
              return (value as { algorithm: string; hash: string }[])
                .filter(({ hash }) => hash !== '')
                .map((hash) => (
                  <Grid key={hash.algorithm} size={6}>
                    <LabelItemCopy label={`${hash.algorithm} - hashes`} value={hash.hash} />
                  </Grid>
                ));
            }

            if (key === 'startup_info') {
              return (value as { key: string; value: string }[])
                .map((v) => (
                  <Grid key={v.key} size={6}>
                    <LabelItemCopy label={`${v.key} - startup_info`} value={v.value} />
                  </Grid>
                ));
            }

            if (isVocabularyField(stixCyberObservable.entity_type, key)) {
              return (
                <Grid key={key} size={6}>
                  <>
                    <Typography variant="h3" gutterBottom={true}>
                      {t_i18n(key)}
                    </Typography>
                    <ItemOpenVocab
                      small={false}
                      type={fieldToCategory(
                        stixCyberObservable.entity_type,
                        key,
                      ) ?? ''}
                      value={value}
                    />
                  </>
                </Grid>
              );
            }

            if (key === 'content') {
              return (
                <Grid key={key} size={6}>
                  <>
                    <Typography variant="h3" gutterBottom={true}>
                      {t_i18n('Content')}
                    </Typography>
                    <ExpandableMarkdown
                      source={value}
                      limit={400}
                    />
                  </>
                </Grid>
              );
            }

            const finalValue = useAttributeValueToReadableValue(value, key);

            return (
              <Grid key={key} size={6}>
                <LabelItemCopy label={t_i18n(key.replace('attribute_', ''))} value={finalValue} />
              </Grid>
            );
          })}
        </Grid>

        <Divider />

        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, marginTop: 2.5 }}>
          {stixCyberObservable.entity_type === 'Network-Traffic' && (
            <StixCyberObservableNestedEntities
              entityId={stixCyberObservable.id}
              entityType={stixCyberObservable.entity_type}
              variant="inLine"
            />
          )}

          <StixCyberObservableIndicators
            stixCyberObservable={stixCyberObservable}
          />

          {isObservableAnalysable && (
            <StixCyberObservableMalwareAnalyses
              observableId={stixCyberObservable.id}
            />
          )}
        </Box>
      </Paper>
    </div>
  );
};

export default StixCyberObservableDetails;
