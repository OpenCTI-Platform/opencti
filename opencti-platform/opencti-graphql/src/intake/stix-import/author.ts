import { getInCache, type ImportContext, setInCache } from './context';
import { createIdentity } from './entities/identity';
import { asStr } from './utils';

// pycti resolve_author and get_author: the author of a report built from an external reference,
// recognised from its title
const AUTHORS: [string[], string][] = [
  [['fireeye', 'mandiant'], 'FireEye'],
  [['eset'], 'ESET'],
  [['dragos'], 'Dragos'],
  [['us-cert'], 'US-CERT'],
  [['unit 42', 'unit42', 'palo alto'], 'Palo Alto Networks'],
  [['accenture'], 'Accenture'],
  [['symantec'], 'Symantec'],
  [['trendmicro', 'trend micro'], 'Trend Micro'],
  [['mcafee'], 'McAfee'],
  [['crowdstrike'], 'CrowdStrike'],
  [['securelist', 'kaspersky'], 'Kaspersky'],
  [['f-secure'], 'F-Secure'],
  [['checkpoint'], 'CheckPoint'],
  [['talos'], 'Cisco Talos'],
  [['secureworks'], 'Dell SecureWorks'],
  [['microsoft'], 'Microsoft'],
  [['mitre att&ck'], 'The MITRE Corporation'],
];

const getAuthor = async (context: ImportContext, name: string) => {
  const cached = getInCache(context, name);
  if (cached !== null) {
    return cached;
  }
  const author = await createIdentity(context, { type: 'Organization', name, description: '' });
  setInCache(context, name, author);
  return author;
};

export const resolveAuthor = async (context: ImportContext, title: unknown) => {
  const lowered = asStr(title, 'lower').toLowerCase();
  const match = AUTHORS.find(([keys]) => keys.some((key) => lowered.includes(key)));
  return match ? getAuthor(context, match[1]) : null;
};
