import type { ImportContext } from './context';
import type { StixObject } from './types';
import { UploadFile } from './types';
import {
  asMapping,
  asStr,
  at,
  b64decode,
  basename,
  contains,
  dictGet,
  dictItems,
  getAttributeInExtension,
  iterate,
  pythonLen,
  pythonTitle,
  pythonTruthy,
  required,
  setItem,
} from './utils';
import { field, kw, type Kwargs } from './kwargs';

// pycti/entities/opencti_stix_cyber_observable.py: create and add_file

const STIX_CYBER_OBSERVABLE_ADD = `
  mutation StixCyberObservableAdd(
    $type: String!,
    $stix_id: StixId,
    $x_opencti_score: Int,
    $x_opencti_description: String,
    $createIndicator: Boolean,
    $createdBy: String,
    $objectMarking: [String],
    $objectLabel: [String],
    $objectOrganization: [String],
    $externalReferences: [String],
    $update: Boolean,
    $upsertOperations: [EditInput!],
    $AutonomousSystem: AutonomousSystemAddInput,
    $Directory: DirectoryAddInput,
    $DomainName: DomainNameAddInput,
    $EmailAddr: EmailAddrAddInput,
    $EmailMessage: EmailMessageAddInput,
    $EmailMimePartType: EmailMimePartTypeAddInput,
    $Artifact: ArtifactAddInput,
    $StixFile: StixFileAddInput,
    $X509Certificate: X509CertificateAddInput,
    $IPv4Addr: IPv4AddrAddInput,
    $IPv6Addr: IPv6AddrAddInput,
    $MacAddr: MacAddrAddInput,
    $Mutex: MutexAddInput,
    $NetworkTraffic: NetworkTrafficAddInput,
    $Process: ProcessAddInput,
    $Software: SoftwareAddInput,
    $Url: UrlAddInput,
    $UserAccount: UserAccountAddInput,
    $WindowsRegistryKey: WindowsRegistryKeyAddInput,
    $WindowsRegistryValueType: WindowsRegistryValueTypeAddInput,
    $CryptographicKey: CryptographicKeyAddInput,
    $CryptocurrencyWallet: CryptocurrencyWalletAddInput,
    $Hostname: HostnameAddInput
    $Text: TextAddInput,
    $UserAgent: UserAgentAddInput
    $BankAccount: BankAccountAddInput
    $PhoneNumber: PhoneNumberAddInput
    $Credential: CredentialAddInput
    $TrackingNumber: TrackingNumberAddInput
    $PaymentCard: PaymentCardAddInput
    $Persona: PersonaAddInput
    $MediaContent: MediaContentAddInput
    $SSHKey: SSHKeyAddInput
    $AIPrompt: AIPromptAddInput
    $IMEI: IMEIAddInput
    $ICCID: ICCIDAddInput
    $IMSI: IMSIAddInput
  ) {
    stixCyberObservableAdd(
      type: $type,
      stix_id: $stix_id,
      x_opencti_score: $x_opencti_score,
      x_opencti_description: $x_opencti_description,
      createIndicator: $createIndicator,
      createdBy: $createdBy,
      objectMarking: $objectMarking,
      objectLabel: $objectLabel,
      update: $update,
      upsertOperations: $upsertOperations,
      externalReferences: $externalReferences,
      objectOrganization: $objectOrganization,
      AutonomousSystem: $AutonomousSystem,
      Directory: $Directory,
      DomainName: $DomainName,
      EmailAddr: $EmailAddr,
      EmailMessage: $EmailMessage,
      EmailMimePartType: $EmailMimePartType,
      Artifact: $Artifact,
      StixFile: $StixFile,
      X509Certificate: $X509Certificate,
      IPv4Addr: $IPv4Addr,
      IPv6Addr: $IPv6Addr,
      MacAddr: $MacAddr,
      Mutex: $Mutex,
      NetworkTraffic: $NetworkTraffic,
      Process: $Process,
      Software: $Software,
      Url: $Url,
      UserAccount: $UserAccount,
      WindowsRegistryKey: $WindowsRegistryKey,
      WindowsRegistryValueType: $WindowsRegistryValueType,
      CryptographicKey: $CryptographicKey,
      CryptocurrencyWallet: $CryptocurrencyWallet,
      Hostname: $Hostname,
      Text: $Text,
      UserAgent: $UserAgent
      BankAccount: $BankAccount
      PhoneNumber: $PhoneNumber
      Credential: $Credential
      TrackingNumber: $TrackingNumber
      PaymentCard: $PaymentCard
      Persona: $Persona
      MediaContent: $MediaContent
      SSHKey: $SSHKey
      AIPrompt: $AIPrompt
      IMEI: $IMEI
      ICCID: $ICCID
      IMSI: $IMSI
    ) {
      id standard_id entity_type parent_types
    }
  }
`;

const STIX_CYBER_OBSERVABLE_IMPORT_PUSH = `
  mutation StixCyberObservableEdit($id: ID!, $file: Upload!, $fileMarkings: [String], $version: DateTime, $noTriggerImport: Boolean, $embedded: Boolean) {
    stixCyberObservableEdit(id: $id) {
      importPush(file: $file, version: $version, fileMarkings: $fileMarkings, noTriggerImport: $noTriggerImport, embedded: $embedded) {
        id
        name
      }
    }
  }
`;

const STIX_CYBER_OBSERVABLE_ADD_RELATION = `
  mutation StixCyberObservableAddRelation($id: ID!, $input: StixRefRelationshipAddInput!) {
    stixCyberObservableEdit(id: $id) {
      relationAdd(input: $input) {
        id
      }
    }
  }
`;

// pycti create: the platform type of a title-cased STIX type (legacy x-opencti-* types included)
const TYPE_RENAMES = new Map<string, string>(Object.entries({
  file: 'StixFile',
  'ipv4-addr': 'IPv4-Addr',
  'ipv6-addr': 'IPv6-Addr',
  persona: 'Persona',
  'ssh-key': 'SSH-Key',
  'ai-prompt': 'AI-Prompt',
  hostname: 'Hostname',
  'x-opencti-hostname': 'Hostname',
  'payment-card': 'Payment-Card',
  'x-opencti-payment-card': 'Payment-Card',
  credential: 'Credential',
  'x-opencti-credential': 'Credential',
  'tracking-number': 'Tracking-Number',
  'x-opencti-tracking-number': 'Tracking-Number',
  'cryptocurrency-wallet': 'Cryptocurrency-Wallet',
  'x-opencti-cryptocurrency-wallet': 'Cryptocurrency-Wallet',
  'user-agent': 'User-Agent',
  'x-opencti-user-agent': 'User-Agent',
  'cryptographic-key': 'Cryptographic-Key',
  'x-opencti-cryptographic-key': 'Cryptographic-Key',
  imei: 'IMEI',
  'x-opencti-imei': 'IMEI',
  iccid: 'ICCID',
  'x-opencti-iccid': 'ICCID',
  imsi: 'IMSI',
  'x-opencti-imsi': 'IMSI',
  text: 'Text',
  'x-opencti-text': 'Text',
}));

// A field of a type input: [input key, observable key, default]. REQUIRED marks pycti's direct
// indexing (observable_data["number"]): absent, the creation fails with a KeyError as in pycti.
const REQUIRED = Symbol('required');
type InputField = [string, string, unknown?];
// Which file inputs a type input carries: all four, all but embedded (AI-Prompt), or none
type FilesInputs = 'all' | 'no-embedded' | 'none';
interface TypeInput {
  variable: string;
  hashes?: boolean;
  fields: InputField[];
  files: FilesInputs;
}

const VALUE_ONLY: InputField[] = [['value', 'value']];

const TYPE_INPUTS = new Map<string, TypeInput>([
  ['Autonomous-System', { variable: 'AutonomousSystem', files: 'all', fields: [['number', 'number', REQUIRED], ['name', 'name'], ['rir', 'rir']] }],
  ['Directory', {
    variable: 'Directory',
    files: 'all',
    fields: [['path', 'path', REQUIRED], ['path_enc', 'path_enc'], ['ctime', 'ctime'], ['mtime', 'mtime'], ['atime', 'atime']],
  }],
  ['Domain-Name', { variable: 'DomainName', files: 'all', fields: [['value', 'value', REQUIRED]] }],
  ['Email-Addr', { variable: 'EmailAddr', files: 'all', fields: [['value', 'value', REQUIRED], ['display_name', 'display_name']] }],
  ['Email-Message', {
    variable: 'EmailMessage',
    files: 'all',
    fields: [['is_multipart', 'is_multipart'], ['attribute_date', 'date'], ['message_id', 'message_id'], ['subject', 'subject'], ['received_lines', 'received_lines'], ['body', 'body']],
  }],
  ['Email-Mime-Part-Type', { variable: 'EmailMimePartType', files: 'all', fields: [['body', 'body'], ['content_type', 'content_type'], ['content_disposition', 'content_disposition']] }],
  ['Artifact', {
    variable: 'Artifact',
    hashes: true,
    files: 'all',
    fields: [['mime_type', 'mime_type'], ['url', 'url'], ['encryption_algorithm', 'encryption_algorithm'], ['decryption_key', 'decryption_key'], ['x_opencti_additional_names', 'x_opencti_additional_names']],
  }],
  ['StixFile', {
    variable: 'StixFile',
    hashes: true,
    files: 'all',
    fields: [['size', 'size'], ['name', 'name'], ['name_enc', 'name_enc'], ['magic_number_hex', 'magic_number_hex'], ['mime_type', 'mime_type'], ['mtime', 'mtime'],
      ['ctime', 'ctime'], ['atime', 'atime'], ['x_opencti_additional_names', 'x_opencti_additional_names']],
  }],
  ['X509-Certificate', {
    variable: 'X509Certificate',
    hashes: true,
    files: 'all',
    fields: [
      ['is_self_signed', 'is_self_signed', false], ['version', 'version'], ['serial_number', 'serial_number'], ['signature_algorithm', 'signature_algorithm'], ['issuer', 'issuer'],
      ['validity_not_before', 'validity_not_before'], ['validity_not_after', 'validity_not_after'], ['subject', 'subject'],
      ['subject_public_key_algorithm', 'subject_public_key_algorithm'], ['subject_public_key_modulus', 'subject_public_key_modulus'],
      ['subject_public_key_exponent', 'subject_public_key_exponent'], ['basic_constraints', 'basic_constraints'], ['name_constraints', 'name_constraints'],
      ['policy_constraints', 'policy_constraints'], ['key_usage', 'key_usage'], ['extended_key_usage', 'extended_key_usage'],
      ['subject_key_identifier', 'subject_key_identifier'], ['authority_key_identifier', 'authority_key_identifier'],
      ['subject_alternative_name', 'subject_alternative_name'], ['issuer_alternative_name', 'issuer_alternative_name'],
      ['subject_directory_attributes', 'subject_directory_attributes'], ['crl_distribution_points', 'crl_distribution_points'],
      ['inhibit_any_policy', 'inhibit_any_policy'], ['private_key_usage_period_not_before', 'private_key_usage_period_not_before'],
      ['private_key_usage_period_not_after', 'private_key_usage_period_not_after'], ['certificate_policies', 'certificate_policies'], ['policy_mappings', 'policy_mappings'],
    ],
  }],
  ['SSH-Key', {
    variable: 'SSHKey',
    files: 'all',
    // pycti defaults fingerprint_sha256 to False
    fields: [['key_type', 'key_type'], ['public_key', 'public_key'], ['fingerprint_sha256', 'fingerprint_sha256', false], ['fingerprint_md5', 'fingerprint_md5'],
      ['key_length', 'key_length'], ['comment', 'comment'], ['created', 'created'], ['expiration_date', 'expiration_date']],
  }],
  ['IPv4-Addr', { variable: 'IPv4Addr', files: 'all', fields: VALUE_ONLY }],
  ['IPv6-Addr', { variable: 'IPv6Addr', files: 'all', fields: VALUE_ONLY }],
  ['Mac-Addr', { variable: 'MacAddr', files: 'all', fields: VALUE_ONLY }],
  ['Mutex', { variable: 'Mutex', files: 'all', fields: [['name', 'name']] }],
  ['Network-Traffic', {
    variable: 'NetworkTraffic',
    files: 'all',
    fields: [['start', 'start'], ['end', 'end'], ['is_active', 'is_active'], ['src_port', 'src_port'], ['dst_port', 'dst_port'], ['networkSrc', 'src_ref'],
      ['networkDst', 'dst_ref'], ['protocols', 'protocols'], ['src_byte_count', 'src_byte_count'], ['dst_byte_count', 'dst_byte_count'],
      ['src_packets', 'src_packets'], ['dst_packets', 'dst_packets']],
  }],
  ['Process', {
    variable: 'Process',
    files: 'all',
    fields: [['is_hidden', 'is_hidden'], ['pid', 'pid'], ['created_time', 'created_time'], ['cwd', 'cwd'], ['command_line', 'command_line'], ['environment_variables', 'environment_variables']],
  }],
  ['Software', {
    variable: 'Software',
    files: 'all',
    fields: [['name', 'name'], ['cpe', 'cpe'], ['swid', 'swid'], ['languages', 'languages'], ['vendor', 'vendor'], ['version', 'version'], ['x_opencti_product', 'x_opencti_product']],
  }],
  ['Url', { variable: 'Url', files: 'all', fields: VALUE_ONLY }],
  ['User-Account', {
    variable: 'UserAccount',
    files: 'all',
    fields: [['user_id', 'user_id'], ['credential', 'credential'], ['account_login', 'account_login'], ['account_type', 'account_type'], ['display_name', 'display_name'],
      ['is_service_account', 'is_service_account'], ['is_privileged', 'is_privileged'], ['can_escalate_privs', 'can_escalate_privs'], ['is_disabled', 'is_disabled'],
      ['account_created', 'account_created'], ['account_expires', 'account_expires'], ['credential_last_changed', 'credential_last_changed'],
      ['account_first_login', 'account_first_login'], ['account_last_login', 'account_last_login']],
  }],
  ['Windows-Registry-Key', {
    variable: 'WindowsRegistryKey',
    files: 'all',
    fields: [['attribute_key', 'key'], ['modified_time', 'modified_time'], ['number_of_subkeys', 'number_of_subkeys']],
  }],
  ['Windows-Registry-Value-Type', { variable: 'WindowsRegistryValueType', files: 'all', fields: [['name', 'name'], ['data', 'data'], ['data_type', 'data_type']] }],
  ['User-Agent', { variable: 'UserAgent', files: 'all', fields: VALUE_ONLY }],
  ['Cryptographic-Key', { variable: 'CryptographicKey', files: 'all', fields: VALUE_ONLY }],
  ['Hostname', { variable: 'Hostname', files: 'all', fields: VALUE_ONLY }],
  ['AI-Prompt', { variable: 'AIPrompt', files: 'no-embedded', fields: VALUE_ONLY }],
  ['Text', { variable: 'Text', files: 'all', fields: VALUE_ONLY }],
  ['Bank-Account', { variable: 'BankAccount', files: 'all', fields: [['iban', 'iban'], ['bic', 'bic'], ['account_number', 'account_number']] }],
  ['Phone-Number', { variable: 'PhoneNumber', files: 'all', fields: VALUE_ONLY }],
  ['Payment-Card', {
    variable: 'PaymentCard',
    files: 'all',
    fields: [['card_number', 'card_number'], ['expiration_date', 'expiration_date'], ['cvv', 'cvv'], ['holder_name', 'holder_name']],
  }],
  ['Media-Content', {
    variable: 'MediaContent',
    files: 'all',
    fields: [['title', 'title'], ['content', 'content'], ['media_category', 'media_category'], ['url', 'url'], ['publication_date', 'publication_date']],
  }],
  ['Persona', { variable: 'Persona', files: 'all', fields: [['persona_name', 'persona_name'], ['persona_type', 'persona_type']] }],
  ['Cryptocurrency-Wallet', { variable: 'CryptocurrencyWallet', files: 'all', fields: VALUE_ONLY }],
  ['Credential', { variable: 'Credential', files: 'all', fields: VALUE_ONLY }],
  ['Tracking-Number', { variable: 'TrackingNumber', files: 'all', fields: VALUE_ONLY }],
  ['IMEI', { variable: 'IMEI', files: 'none', fields: VALUE_ONLY }],
  ['ICCID', { variable: 'ICCID', files: 'none', fields: VALUE_ONLY }],
  ['IMSI', { variable: 'IMSI', files: 'none', fields: VALUE_ONLY }],
]);

// pycti stix_cyber_observable.add_file (with its data given, as create calls it)
const addObservableFile = async (context: ImportContext, kwargs: Kwargs) => {
  const id = kw(kwargs, 'id');
  const fileName = kw(kwargs, 'file_name');
  const data = kw(kwargs, 'data') as Buffer;
  const mimeType = kw(kwargs, 'mime_type', 'text/plain') as string;
  const noTriggerImport = kw(kwargs, 'no_trigger_import', false);
  if (id === null || id === undefined || fileName === null || fileName === undefined) {
    context.logger.error('[opencti_stix_cyber_observable] Missing parameters: id or file_name');
    return null;
  }
  return context.client.query(STIX_CYBER_OBSERVABLE_IMPORT_PUSH, {
    id,
    file: new UploadFile(basename(fileName), data, mimeType),
    fileMarkings: kw(kwargs, 'fileMarkings'),
    version: kw(kwargs, 'version'),
    noTriggerImport: typeof noTriggerImport === 'boolean' ? noTriggerImport : noTriggerImport === 'True',
    embedded: kw(kwargs, 'embedded', false),
  });
};

const backfillAdditionalNames = (observableData: StixObject) => {
  if (!contains(observableData, 'x_opencti_additional_names') && getAttributeInExtension('additional_names', observableData) !== null) {
    setItem(observableData, 'x_opencti_additional_names', getAttributeInExtension('additional_names', observableData));
  }
};

// pycti stix_cyber_observable.create: observableData is the STIX object itself (mutated as pycti
// does), or a simple observable (key "Type.attribute" and its value)
export const createStixCyberObservable = async (context: ImportContext, kwargs: Kwargs): Promise<any> => {
  const observableData: StixObject = kw(kwargs, 'observableData', {}) as StixObject;
  const simpleObservableId = kw(kwargs, 'simple_observable_id');
  const simpleObservableKey = kw(kwargs, 'simple_observable_key') as string | null;
  const simpleObservableValue = kw(kwargs, 'simple_observable_value');
  const simpleObservableDescription = kw(kwargs, 'simple_observable_description');
  let xOpenctiScore = kw(kwargs, 'x_opencti_score');
  const createdBy = kw(kwargs, 'createdBy');
  const objectMarking = kw(kwargs, 'objectMarking');
  const objectLabel = kw(kwargs, 'objectLabel');
  const update = kw(kwargs, 'update', false);
  const files = kw(kwargs, 'files');
  const filesMarkings = kw(kwargs, 'filesMarkings');
  const noTriggerImport = kw(kwargs, 'noTriggerImport');
  const embedded = kw(kwargs, 'embedded');

  const createIndicator = contains(observableData, 'x_opencti_create_indicator') ? required(observableData, 'x_opencti_create_indicator') : kw(kwargs, 'createIndicator', false);
  let attribute: string | null = null;
  let type: string | null;
  if (simpleObservableKey !== null && simpleObservableKey !== undefined) {
    // pycti raises an IndexError on a key without a dot
    const keySplit = asStr(simpleObservableKey, 'split').split('.');
    type = pythonTitle(keySplit[0]);
    attribute = at(keySplit, 1) as string;
    if (attribute !== 'hashes' && attribute !== 'extensions') {
      setItem(observableData, attribute, simpleObservableValue);
    }
  } else {
    type = contains(observableData, 'type') ? pythonTitle(asStr(required(observableData, 'type'), 'title')) : null;
  }
  if (type === null) {
    return null;
  }
  type = TYPE_RENAMES.get(type.toLowerCase()) ?? type;

  let xOpenctiDescription = contains(observableData, 'x_opencti_description')
    ? required(observableData, 'x_opencti_description')
    : getAttributeInExtension('description', observableData);
  if (simpleObservableDescription !== null && simpleObservableDescription !== undefined) {
    xOpenctiDescription = simpleObservableDescription;
  }
  if (contains(observableData, 'x_opencti_score')) {
    xOpenctiScore = required(observableData, 'x_opencti_score');
  } else if (getAttributeInExtension('score', observableData) !== null) {
    xOpenctiScore = getAttributeInExtension('score', observableData);
  }
  let stixId = field(observableData, 'id');
  if (simpleObservableId !== null && simpleObservableId !== undefined) {
    stixId = simpleObservableId;
  }

  const hashes: { algorithm: string; hash: unknown }[] = [];
  const loweredKey = simpleObservableKey !== null && simpleObservableKey !== undefined ? simpleObservableKey.toLowerCase() : null;
  if (loweredKey === 'file.hashes.md5') {
    hashes.push({ algorithm: 'MD5', hash: simpleObservableValue });
  }
  if (loweredKey === 'file.hashes.sha-1') {
    hashes.push({ algorithm: 'SHA-1', hash: simpleObservableValue });
  }
  if (loweredKey === 'file.hashes.sha-256') {
    hashes.push({ algorithm: 'SHA-256', hash: simpleObservableValue });
  }
  if (contains(observableData, 'hashes')) {
    dictItems(required(observableData, 'hashes')).forEach(([algorithm, hash]) => hashes.push({ algorithm, hash }));
  }

  const inputVariables: Record<string, unknown> = {
    type,
    stix_id: stixId,
    x_opencti_score: xOpenctiScore,
    x_opencti_description: xOpenctiDescription,
    createIndicator,
    createdBy,
    objectMarking,
    objectOrganization: kw(kwargs, 'objectOrganization'),
    objectLabel,
    externalReferences: kw(kwargs, 'externalReferences'),
    update,
    upsertOperations: kw(kwargs, 'upsert_operations'),
  };
  if (type === 'Artifact' || type === 'StixFile') {
    backfillAdditionalNames(observableData);
  } else if (type === 'Software' && !contains(observableData, 'x_opencti_product') && getAttributeInExtension('x_opencti_product', observableData) !== null) {
    setItem(observableData, 'x_opencti_product', getAttributeInExtension('x_opencti_product', observableData));
  }
  const typeInput = TYPE_INPUTS.get(type);
  if (typeInput) {
    const input: Record<string, unknown> = {};
    if (typeInput.hashes) {
      input.hashes = hashes.length > 0 ? hashes : null;
    }
    typeInput.fields.forEach(([inputKey, sourceKey, defaultValue = null]) => {
      input[inputKey] = defaultValue === REQUIRED ? required(observableData, sourceKey) : field(observableData, sourceKey, defaultValue);
    });
    if (typeInput.files !== 'none') {
      input.files = files;
      input.filesMarkings = filesMarkings;
      input.noTriggerImport = noTriggerImport;
      if (typeInput.files === 'all') {
        input.embedded = embedded;
      }
    }
    if (type === 'Domain-Name' && attribute !== null) {
      setItem(input, attribute, simpleObservableValue);
    }
    inputVariables[typeInput.variable] = input;
  }
  const data = await context.client.query(STIX_CYBER_OBSERVABLE_ADD, inputVariables);
  const result = data.stixCyberObservableAdd;
  if (contains(observableData, 'payload_bin') && contains(observableData, 'mime_type')) {
    await addObservableFile(context, {
      id: result.id,
      file_name: contains(observableData, 'x_opencti_additional_names') && pythonLen(required(observableData, 'x_opencti_additional_names')) > 0 ? at(required(observableData, 'x_opencti_additional_names'), 0) : 'artifact.bin',
      data: b64decode(required(observableData, 'payload_bin')),
      mime_type: required(observableData, 'mime_type'),
    });
  }
  if (type === 'Windows-Registry-Key' && pythonTruthy(dictGet(observableData, 'values'))) {
    const keyId = result.id;
    for (const registryValue of iterate(required(observableData, 'values'))) {
      const valueResult = await createStixCyberObservable(context, {
        observableData: { type: 'windows-registry-value-type', ...asMapping(registryValue) },
        createdBy,
        objectMarking,
        objectLabel,
        update,
      });
      if (valueResult !== null && valueResult !== undefined) {
        await context.client.query(STIX_CYBER_OBSERVABLE_ADD_RELATION, {
          id: keyId,
          input: { toId: valueResult.id, relationship_type: 'values' },
        });
      }
    }
  }
  return result;
};
