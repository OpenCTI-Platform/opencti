import { AUTOMATION, BYPASS, KNOWLEDGE, TAXIIAPI } from '../utils/access';
import { KNOWLEDGE_COLLABORATION, KNOWLEDGE_FORM_INTAKE, KNOWLEDGE_FRONTEND_EXPORT, KNOWLEDGE_SHARE_FILTERS, KNOWLEDGE_UPDATE } from './general';

// The capabilities defined by the platform, created at initialization by createCapabilities (database/data-initialization).
// Constants only: this file must stay importable without loading the platform bootstrap.
export interface CapabilityDefinition {
  name: string;
  description: string;
  attribute_order: number;
  dependencies?: CapabilityDefinition[];
}

// region Platform capabilities definition
const BYPASS_CAPABILITIES: CapabilityDefinition = { name: BYPASS, description: 'Bypass all capabilities', attribute_order: 1 };
export const TAXII_CAPABILITIES: CapabilityDefinition = {
  name: TAXIIAPI,
  attribute_order: 2500,
  description: 'Access data sharing',
  dependencies: [
    { name: 'SETCOLLECTIONS', description: 'Manage data sharing', attribute_order: 2510 },
  ],
};
// Sibling of KNUPDATE on purpose: capabilities are matched by name inclusion, a child of KNUPDATE would imply it.
export const FORM_INTAKE_CAPABILITY: CapabilityDefinition = { name: KNOWLEDGE_FORM_INTAKE, description: 'Create knowledge via Form Intake', attribute_order: 350 };
export const SHARE_FILTERS_CAPABILITY: CapabilityDefinition = { name: KNOWLEDGE_SHARE_FILTERS, description: 'Share filters', attribute_order: 950 };
const KNOWLEDGE_CAPABILITIES: CapabilityDefinition = {
  name: KNOWLEDGE,
  description: 'Access knowledge',
  attribute_order: 100,
  dependencies: [
    { name: KNOWLEDGE_COLLABORATION, description: 'Access to collaborative creation', attribute_order: 150 },
    { name: KNOWLEDGE_FRONTEND_EXPORT, description: 'Can use web interface export functions (PDF, PNG, etc.)', attribute_order: 160 },
    {
      name: KNOWLEDGE_UPDATE,
      description: 'Create / Update knowledge',
      attribute_order: 200,
      dependencies: [
        { name: 'KNORGARESTRICT', description: 'Restrict organization access', attribute_order: 290 },
        { name: 'KNDELETE', description: 'Delete knowledge', attribute_order: 300 },
        { name: 'KNMERGE', description: 'Merge knowledge', attribute_order: 305 },
        { name: 'KNMANAGEAUTHMEMBERS', description: 'Manage authorized members', attribute_order: 310 },
        { name: 'KNBYPASSREFERENCE', description: 'Bypass enforced reference', attribute_order: 320 },
        { name: 'KNBYPASSFIELDS', description: 'Bypass mandatory fields', attribute_order: 330 },
      ],
    },
    FORM_INTAKE_CAPABILITY,
    { name: 'KNUPLOAD', description: 'Upload knowledge files', attribute_order: 400 },
    { name: 'KNASKIMPORT', description: 'Import knowledge', attribute_order: 500 },
    {
      name: 'KNGETEXPORT',
      description: 'Download knowledge export',
      attribute_order: 700,
      dependencies: [{ name: 'KNASKEXPORT', description: 'Generate knowledge export', attribute_order: 710 }],
    },
    { name: 'KNENRICHMENT', description: 'Ask for knowledge enrichment', attribute_order: 800 },
    { name: 'KNDISSEMINATION', description: 'Disseminate files by email', attribute_order: 900 },
    SHARE_FILTERS_CAPABILITY,
  ],
};
export const SETTINGS_CAPABILITIES: CapabilityDefinition = {
  name: 'SETTINGS',
  description: 'Access to admin functionalities',
  attribute_order: 3000,
  dependencies: [
    { name: 'SETPARAMETERS', description: 'Manage parameters', attribute_order: 3100 },
    { name: 'SETACCESSES', description: 'Manage credentials', attribute_order: 3200 },
    { name: 'SETAUTH', description: 'Manage authentication', attribute_order: 3220 },
    { name: 'SETMARKINGS', description: 'Manage marking definitions', attribute_order: 3300 },
    { name: 'SETDISSEMINATION', description: 'Manage dissemination lists', attribute_order: 3320 },
    { name: 'SETCUSTOMIZATION', description: 'Manage customization', attribute_order: 3350 },
    { name: 'SETLABELS', description: 'Manage labels', attribute_order: 3400 },
    { name: 'SETVOCABULARIES', description: 'Manage vocabularies', attribute_order: 3410 },
    { name: 'SETCASETEMPLATES', description: 'Manage case templates', attribute_order: 3420 },
    { name: 'SETSTATUSTEMPLATES', description: 'Manage status templates', attribute_order: 3430 },
    { name: 'SETKILLCHAINPHASES', description: 'Manage kill chain phases', attribute_order: 3440 },
    { name: 'SETMANAGEXTMHUB', description: 'Manage XTM Hub', attribute_order: 3450 },
    { name: 'SECURITYACTIVITY', description: 'Access security activity', attribute_order: 3500 },
    { name: 'FILEINDEXING', description: 'Access to file indexing', attribute_order: 3600 },
    { name: 'SUPPORT', description: 'Access to support data', attribute_order: 3700 },
  ],
};
const PIR_CAPABILITIES: CapabilityDefinition = {
  name: 'PIRAPI',
  description: 'Access PIR',
  attribute_order: 2900,
  dependencies: [
    {
      name: 'PIRUPDATE',
      description: 'Create / Update / Delete PIR',
      attribute_order: 2950,
    },
  ],
};
const AUTOMATION_CAPABILITIES: CapabilityDefinition = {
  name: AUTOMATION,
  description: 'Use Playbooks',
  attribute_order: 2800,
  dependencies: [
    {
      name: 'AUTMANAGE',
      description: 'Manage Playbooks',
      attribute_order: 2850,
    },
  ],
};
export const API_ACCESS_CAPABILITIES: CapabilityDefinition = {
  name: 'APIACCESS',
  attribute_order: 2200,
  description: 'API usage with authorization header',
  dependencies: [
    { name: 'USETOKEN', description: 'Allow token usage', attribute_order: 2250 },
    { name: 'USEBASICAUTH', description: 'Allow basic auth usage', attribute_order: 2290 },
  ],
};
export const CAPABILITIES: CapabilityDefinition[] = [
  BYPASS_CAPABILITIES,
  KNOWLEDGE_CAPABILITIES,
  {
    name: 'EXPLORE',
    description: 'Access dashboards',
    attribute_order: 1000,
    dependencies: [
      {
        name: 'EXUPDATE',
        description: 'Create / Update dashboards',
        attribute_order: 1100,
        dependencies: [
          { name: 'EXDELETE', description: 'Delete dashboards', attribute_order: 1200 },
          { name: 'PUBLISH', description: 'Manage public dashboards', attribute_order: 1300 },
        ],
      },
    ],
  },
  {
    name: 'INVESTIGATION',
    description: 'Access investigations',
    attribute_order: 1400,
    dependencies: [
      {
        name: 'INUPDATE',
        description: 'Create / Update investigations',
        attribute_order: 1410,
        dependencies: [
          { name: 'INDELETE', description: 'Delete investigations', attribute_order: 1420 },
        ],
      },
    ],
  },
  {
    name: 'MODULES',
    description: 'Access connectors',
    attribute_order: 2000,
    dependencies: [{ name: 'MODMANAGE', description: 'Manage connector state', attribute_order: 2100 }],
  },
  TAXII_CAPABILITIES,
  PIR_CAPABILITIES,
  AUTOMATION_CAPABILITIES,
  SETTINGS_CAPABILITIES,
  API_ACCESS_CAPABILITIES,
  {
    name: 'CONNECTORAPI',
    attribute_order: 2300,
    description: 'Connectors API usage: register, ping, export push ...',
  },
  {
    name: 'INGESTION',
    attribute_order: 2600,
    description: 'Access ingestion',
    dependencies: [
      { name: 'SETINGESTIONS', description: 'Manage ingestion', attribute_order: 2610 },
    ],
  },
  {
    name: 'CSVMAPPERS',
    description: 'Manage data mappers',
    attribute_order: 2700,
  },
];
// endregion

/**
 * Finds the description of a capability in the capabilities defined by the platform (CAPABILITIES).
 * The description is the English text shown in the roles, also used as its translation key by the front.
 *
 * @param capabilityName full name of the capability, as created by createCapabilities:
 * the names of its parents joined by _ (e.g. CONNECTORAPI, INGESTION_SETINGESTIONS)
 * @returns its description, undefined for an unknown name (a nested capability by its short name included)
 */
export const findCapabilityDescription = (capabilityName: string): string | undefined => {
  const findCapabilityInTree = (capabilities: CapabilityDefinition[], parentName: string): string | undefined => {
    for (let i = 0; i < capabilities.length; i += 1) {
      const capability = capabilities[i];
      const name = `${parentName}${capability.name}`;
      if (name === capabilityName) {
        return capability.description;
      }
      const description = capability.dependencies ? findCapabilityInTree(capability.dependencies, `${name}_`) : undefined;
      if (description) {
        return description;
      }
    }
    return undefined;
  };
  return findCapabilityInTree(CAPABILITIES, '');
};
