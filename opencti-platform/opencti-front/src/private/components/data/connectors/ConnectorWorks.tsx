/* eslint-disable @typescript-eslint/no-explicit-any */
// TODO : remove this line (needed to don't crash test with example array)
/* eslint max-len: ["error", { "code": 7000, "ignoreComments": true }] */
import React, { FunctionComponent, useEffect, useState } from 'react';
import { graphql, createRefetchContainer, RelayRefetchProp } from 'react-relay';
import Grid from '@mui/material/Grid';
import Typography from '@mui/material/Typography';
import LinearProgress from '@mui/material/LinearProgress';
import Paper from '@mui/material/Paper';
import Button from '@mui/material/Button';
import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableContainer from '@mui/material/TableContainer';
import TableHead from '@mui/material/TableHead';
import TableRow from '@mui/material/TableRow';
import Tooltip from '@mui/material/Tooltip';
import { interval } from 'rxjs';
import { Delete } from 'mdi-material-ui';
import makeStyles from '@mui/styles/makeStyles';
import Drawer from '@components/common/drawer/Drawer';
import Alert from '@mui/material/Alert';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import { ConnectorWorksQuery$variables } from './__generated__/ConnectorWorksQuery.graphql';
import { ConnectorWorks_data$data } from './__generated__/ConnectorWorks_data.graphql';
import TaskStatus from '../../../../components/TaskStatus';
import { useFormatter } from '../../../../components/i18n';
import { FIVE_SECONDS } from '../../../../utils/Time';
import { MESSAGING$ } from '../../../../relay/environment';
import { MODULES_MODMANAGE } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import ConnectorWorksErrorLine, { ParsedWorkMessage } from './ConnectorWorksErrorLine';
import { getMainRepresentative } from '../../../../utils/defaultRepresentatives';

const interval$ = interval(FIVE_SECONDS);

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  paper: {
    margin: '10px 0 20px 0',
    padding: '15px',
    borderRadius: 4,
    position: 'relative',
  },
  number: {
    fontWeight: 600,
    fontSize: 18,
  },
  progress: {
    borderRadius: 4,
    height: 10,
  },
  bottomTypo: {
    marginTop: 20,
  },
  errorButton: {
    position: 'absolute',
    right: 10,
    top: 10,
  },
  deleteButton: {
    position: 'absolute',
    right: 10,
    bottom: 10,
  },
}));

export const connectorWorksWorkDeletionMutation = graphql`
  mutation ConnectorWorksWorkDeletionMutation($id: ID!) {
    workEdit(id: $id) {
      delete
    }
  }
`;

export type WorkMessages = {
  message: string,
  sequence: number,
  source: string,
  timestamp: string,
};

interface ConnectorWorksComponentProps {
  data: ConnectorWorks_data$data
  options: ConnectorWorksQuery$variables[]
  relay: RelayRefetchProp
}

const criticalErrorTypes = [
  'MULTIPLE_REFERENCES_ERROR',
  'UNSUPPORTED_ERROR',
  'DATABASE_ERROR',
  'INTERNAL_SERVER_ERROR',
];

const warningErrorTypes = [
  'VALIDATION_ERROR',
  'MULTIPLE_ENTITIES_ERROR',
  'ACL_ERROR',
  'MISSING_REFERENCE_ERROR',
];

// TODO : Remove
// const examples: WorkMessages[] = [
//   {
//     'timestamp': '2024-10-11T20:10:06.788Z',
//     'message': 'Sample',
//     'sequence': null,
//     'source': '{"type": "relationship", "spec_version": "2.1", "id": "relationship--799f653d-da5c-53ac-86d2-2046f1c93378", "created_by_ref": "identity--180d3ffd-a014-54ff-a817-211dddd29059", "created": "2024-10-11T17:19:43.689008Z", "modified": "2024-10-11T17:19:43.689008Z", "relationship_type": "originates-from", "source_ref": "intrusion-set--826cb3d9-0de3-5af7-9e95-f64fa12501a0", "target_ref": "location--efa1b9b0-dc59-5bad-baa2-4fc495e55fcc", "object_marking_refs": ["marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"], "nb_deps": 1, "x_opencti_granted_refs": null, "x_opencti_workflow_id": null}'
//   },
//   {
//     'timestamp': '2024-10-11T20:10:06.788Z',
//     'message': '{\'name\': \'UNSUPPORTED_ERROR\', \'error_message\': \'Input resolve refs expect single value\'}',
//     'sequence': null,
//     'source': '{"type": "relationship", "spec_version": "2.1", "id": "relationship--799f653d-da5c-53ac-86d2-2046f1c93378", "created_by_ref": "identity--180d3ffd-a014-54ff-a817-211dddd29059", "created": "2024-10-11T17:19:43.689008Z", "modified": "2024-10-11T17:19:43.689008Z", "relationship_type": "originates-from", "source_ref": "intrusion-set--826cb3d9-0de3-5af7-9e95-f64fa12501a0", "target_ref": "location--efa1b9b0-dc59-5bad-baa2-4fc495e55fcc", "object_marking_refs": ["marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"], "nb_deps": 1, "x_opencti_granted_refs": null, "x_opencti_workflow_id": null}'
//   },
//   {
//     'timestamp': '2024-10-11T08:18:52.589Z',
//     'message': 'IpInfo Rate limit exceeded',
//     'sequence': null,
//     'source': null
//   },
//   {
//     'timestamp': '2024-10-12T07:35:10.930Z',
//     'message': 'Expecting value: line 1 column 1 (char 0)',
//     'sequence': null,
//     'source': null
//   },
//   {
//     'timestamp': '2024-07-19T08:39:04.041Z',
//     'message': '{\'name\': \'MISSING_REFERENCE_ERROR\', \'error_message\': \'Element(s) not found\', \'http_status\': 404, \'genre\': \'BUSINESS\', \'unresolvedIds\': [\'text--fb495702-27c9-5767-a620-364dd8a16c53\']}',
//     'sequence': null,
//     'source': '{"type": "relationship", "spec_version": "2.1", "id": "relationship--b23c3199-cbae-570d-8986-d39841f1ddbd", "created_by_ref": "identity--d10c6f1c-e3ee-588c-a846-31612bc780ec", "created": "2024-07-19T08:36:38.533026Z", "modified": "2024-07-19T08:36:38.533026Z", "relationship_type": "related-to", "source_ref": "text--fb495702-27c9-5767-a620-364dd8a16c53", "target_ref": "file--42e66cd1-b2cc-53c3-b857-fbd6fd7e0daa", "nb_deps": 1, "x_opencti_granted_refs": null, "x_opencti_workflow_id": null}'
//   },
//   {
//     'timestamp': '2024-07-19T08:39:04.882Z',
//     'message': '{\'name\': \'MISSING_REFERENCE_ERROR\', \'error_message\': \'Element(s) not found\', \'http_status\': 404, \'genre\': \'BUSINESS\', \'unresolvedIds\': [\'text--54faee67-326a-55f9-86c9-da1bc8d26acf\']}',
//     'sequence': null,
//     'source': '{"type": "relationship", "spec_version": "2.1", "id": "relationship--af088183-2210-5ec9-8cd3-c724194354aa", "created_by_ref": "identity--d10c6f1c-e3ee-588c-a846-31612bc780ec", "created": "2024-07-19T08:36:38.536841Z", "modified": "2024-07-19T08:36:38.536841Z", "relationship_type": "related-to", "source_ref": "text--54faee67-326a-55f9-86c9-da1bc8d26acf", "target_ref": "file--92dd0ab7-e092-57df-831f-fb79a2ef4a85", "nb_deps": 1, "x_opencti_granted_refs": null, "x_opencti_workflow_id": null}'
//   },
//   {
//     'timestamp': '2024-07-19T08:39:07.083Z',
//     'message': '{\'name\': \'MISSING_REFERENCE_ERROR\', \'error_message\': \'Element(s) not found\', \'http_status\': 404, \'genre\': \'BUSINESS\', \'unresolvedIds\': [\'text--6dbfdffd-026f-5673-b10c-a78781f6b85a\']}',
//     'sequence': null,
//     'source': '{"type": "relationship", "spec_version": "2.1", "id": "relationship--d94573ea-c703-5639-a039-3c5526f97bcd", "created_by_ref": "identity--d10c6f1c-e3ee-588c-a846-31612bc780ec", "created": "2024-07-19T08:36:38.54045Z", "modified": "2024-07-19T08:36:38.54045Z", "relationship_type": "related-to", "source_ref": "text--6dbfdffd-026f-5673-b10c-a78781f6b85a", "target_ref": "file--835a6f4d-c9b7-51af-aebf-1514a6b2bc34", "nb_deps": 1, "x_opencti_granted_refs": null, "x_opencti_workflow_id": null}'
//   },
//   {
//     'timestamp': '2024-10-07T07:53:40.704Z',
//     'message': '{\'name\': \'FUNCTIONAL_ERROR\', \'error_message\': \'This update will produce a duplicate\'}',
//     'sequence': null,
//     'source': '{"modified": "2024-01-08T20:40:31.822Z", "name": "Dragonfly", "description": "[Dragonfly](https://attack.mitre.org/groups/G0035) is a cyber espionage group that has been attributed to Russia\'s Federal Security Service (FSB) Center 16.(Citation: DOJ Russia Targeting Critical Infrastructure March 2022)(Citation: UK GOV FSB Factsheet April 2022) Active since at least 2010, [Dragonfly](https://attack.mitre.org/groups/G0035) has targeted defense and aviation companies, government entities, companies related to industrial control systems, and critical infrastructure sectors worldwide through supply chain, spearphishing, and drive-by compromise attacks.(Citation: Symantec Dragonfly)(Citation: Secureworks IRON LIBERTY July 2019)(Citation: Symantec Dragonfly Sept 2017)(Citation: Fortune Dragonfly 2.0 Sept 2017)(Citation: Gigamon Berserk Bear October 2021)(Citation: CISA AA20-296A Berserk Bear December 2020)(Citation: Symantec Dragonfly 2.0 October 2017)", "aliases": ["Dragonfly", "TEMP.Isotope", "DYMALLOY", "Berserk Bear", "TG-4192", "Crouching Yeti", "IRON LIBERTY", "Energetic Bear", "Ghost Blizzard", "BROMINE"], "x_mitre_deprecated": false, "x_mitre_version": "4.0", "x_mitre_contributors": ["Dragos Threat Intelligence"], "type": "intrusion-set", "id": "intrusion-set--1c63d4ec-0a75-4daa-b1df-0d11af3d3cc1", "created": "2017-05-31T21:32:05.217Z", "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5", "revoked": false, "external_references": [{"source_name": "mitre-attack", "url": "https://attack.mitre.org/groups/G0035", "external_id": "G0035"}, {"source_name": "CISA AA20-296A Berserk Bear December 2020", "description": "CISA. (2020, December 1). Russian State-Sponsored Advanced Persistent Threat Actor Compromises U.S. Government Targets. Retrieved December 9, 2021.", "url": "https://www.cisa.gov/uscert/ncas/alerts/aa20-296a#revisions"}, {"source_name": "DOJ Russia Targeting Critical Infrastructure March 2022", "description": "Department of Justice. (2022, March 24). Four Russian Government Employees Charged in Two Historical Hacking Campaigns Targeting Critical Infrastructure Worldwide. Retrieved April 5, 2022.", "url": "https://www.justice.gov/opa/pr/four-russian-government-employees-charged-two-historical-hacking-campaigns-targeting-critical"}, {"source_name": "Dragos DYMALLOY ", "description": "Dragos. (n.d.). DYMALLOY. Retrieved August 20, 2020.", "url": "https://www.dragos.com/threat/dymalloy/"}, {"source_name": "Fortune Dragonfly 2.0 Sept 2017", "description": "Hackett, R. (2017, September 6). Hackers Have Penetrated Energy Grid, Symantec Warns. Retrieved June 6, 2018.", "url": "http://fortune.com/2017/09/06/hack-energy-grid-symantec/"}, {"source_name": "Mandiant Ukraine Cyber Threats January 2022", "description": "Hultquist, J. (2022, January 20). Anticipating Cyber Threats as the Ukraine Crisis Escalates. Retrieved January 24, 2022.", "url": "https://www.mandiant.com/resources/ukraine-crisis-cyber-threats"}, {"source_name": "Microsoft Threat Actor Naming July 2023", "description": "Microsoft . (2023, July 12). How Microsoft names threat actors. Retrieved November 17, 2023.", "url": "https://learn.microsoft.com/en-us/microsoft-365/security/intelligence/microsoft-threat-actor-naming?view=o365-worldwide"}, {"source_name": "Secureworks MCMD July 2019", "description": "Secureworks. (2019, July 24). MCMD Malware Analysis. Retrieved August 13, 2020.", "url": "https://www.secureworks.com/research/mcmd-malware-analysis"}, {"source_name": "Secureworks IRON LIBERTY July 2019", "description": "Secureworks. (2019, July 24). Resurgent Iron Liberty Targeting Energy Sector. Retrieved August 12, 2020.", "url": "https://www.secureworks.com/research/resurgent-iron-liberty-targeting-energy-sector"}, {"source_name": "Secureworks Karagany July 2019", "description": "Secureworks. (2019, July 24). Updated Karagany Malware Targets Energy Sector. Retrieved August 12, 2020.", "url": "https://www.secureworks.com/research/updated-karagany-malware-targets-energy-sector"}, {"source_name": "Gigamon Berserk Bear October 2021", "description": "Slowik, J. (2021, October). THE BAFFLING BERSERK BEAR: A DECADE\\u2019S ACTIVITY TARGETING CRITICAL INFRASTRUCTURE. Retrieved December 6, 2021.", "url": "https://vblocalhost.com/uploads/VB2021-Slowik.pdf"}, {"source_name": "Symantec Dragonfly Sept 2017", "description": "Symantec Security Response. (2014, July 7). Dragonfly: Western energy sector targeted by sophisticated attack group. Retrieved September 9, 2017.", "url": "https://docs.broadcom.com/doc/dragonfly_threat_against_western_energy_suppliers"}, {"source_name": "Symantec Dragonfly", "description": "Symantec Security Response. (2014, June 30). Dragonfly: Cyberespionage Attacks Against Energy Suppliers. Retrieved April 8, 2016.", "url": "https://community.broadcom.com/symantecenterprise/communities/community-home/librarydocuments/viewdocument?DocumentKey=7382dce7-0260-4782-84cc-890971ed3f17&CommunityKey=1ecf5f55-9545-44d6-b0f4-4e4a7f5f5e68&tab=librarydocuments"}, {"source_name": "Symantec Dragonfly 2.0 October 2017", "description": "Symantec. (2017, October 7). Dragonfly: Western energy sector targeted by sophisticated attack group. Retrieved April 19, 2022.", "url": "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/dragonfly-energy-sector-cyber-attacks"}, {"source_name": "UK GOV FSB Factsheet April 2022", "description": "UK Gov. (2022, April 5). Russia\'s FSB malign activity: factsheet. Retrieved April 5, 2022.", "url": "https://www.gov.uk/government/publications/russias-fsb-malign-cyber-activity-factsheet/russias-fsb-malign-activity-factsheet"}], "object_marking_refs": ["marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"], "x_mitre_domains": ["enterprise-attack", "ics-attack"], "x_mitre_attack_spec_version": "3.2.0", "x_mitre_modified_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5", "spec_version": "2.1", "nb_deps": 1, "x_opencti_stix_ids": null, "x_opencti_granted_refs": null, "x_opencti_workflow_id": null}'
//   },
//   {
//     'timestamp': '2024-10-11T19:31:53.355Z',
//     'message': '{\'name\': \'FUNCTIONAL_ERROR\', \'error_message\': \'This update will produce a duplicate\'}',
//     'sequence': null,
//     'source': '{"type": "malware", "spec_version": "2.1", "id": "malware--3d52e6f1-28e2-5e41-9b06-0a0432709387", "created_by_ref": "identity--180d3ffd-a014-54ff-a817-211dddd29059", "created": "2024-10-11T16:59:45.162143Z", "modified": "2024-10-11T16:59:45.162143Z", "name": "Gozi", "description": "2000 Ursnif aka Snifula\\r\\n2006 Gozi v1.0, Gozi CRM, CRM, Papras\\r\\n2010 Gozi v2.0, Gozi ISFB, ISFB, Pandemyia(*)\\r\\n-> 2010 Gozi Prinimalka -> Vawtrak/Neverquest\\r\\n\\r\\nIn 2006, Gozi v1.0 (\'Gozi CRM\' aka \'CRM\') aka Papras was first observed.\\r\\nIt was offered as a CaaS, known as 76Service. This first version of Gozi was developed by Nikita Kurmin, and he borrowed code from Ursnif aka Snifula, a spyware developed by Alexey Ivanov around 2000, and some other kits. Gozi v1.0 thus had a formgrabber module and often is classified as Ursnif aka Snifula.\\r\\n\\r\\nIn September 2010, the source code of a particular Gozi CRM dll version was leaked, which led to Vawtrak/Neverquest (in combination with Pony) via Gozi Prinimalka (a slightly modified Gozi v1.0) and Gozi v2.0 (aka \'Gozi ISFB\' aka \'ISFB\' aka Pandemyia). This version came with a webinject module.", "is_family": true, "aliases": ["CRM", "Gozi CRM", "Papras", "Snifula", "Ursnif", "win.gozi"], "external_references": [{"source_name": "Malpedia", "description": "Reference found in the Malpedia library", "url": "https://malpedia.caad.fkie.fraunhofer.de/details/win.gozi"}, {"source_name": "Malpedia", "description": "Reference found in the Malpedia library", "url": "http://blog.malwaremustdie.org/2013/02/the-infection-of-styx-exploit-kit.html"}, {"source_name": "Malpedia", "description": "Reference found in the Malpedia library", "url": "http://researchcenter.paloaltonetworks.com/2017/02/unit42-banking-trojans-ursnif-global-distribution-networks-identified/"}, {"source_name": "Malpedia", "description": "Reference found in the Malpedia library", "url": "https://0xc0decafe.com/malware-analyst-guide-to-pe-timestamps/"}, {"source_name": "Malpedia", "description": "Reference found in the Malpedia library", "url": "https://0xtoxin-labs.gitbook.io/malware-analysis/malware-analysis/gozi-italian-shellcode-dance"}, {"source_name": "Malpedia", "description": "Reference found in the Malpedia library", "url": "https://0xtoxin.github.io/threat%20breakdown/Gozi-Italy-Campaign/"}, {"source_name": "Malpedia", "description": "Reference found in the Malpedia library", "url": "https://blog.gdatasoftware.com/2016/11/29325-analysis-ursnif-spying-on-your-data-since-2007"}, {"source_name": "Malpedia", "description": "Reference found in the Malpedia library", "url": "https://blog.sekoia.io/exposing-fakebat-loader-distribution-methods-and-adversary-infrastructure/"}, {"source_name": "Malpedia", "description": "Reference found in the Malpedia library", "url": "https://blog.talosintelligence.com/2020/12/2020-year-in-malware.html"}, {"source_name": "Malpedia", "description": "Reference found in the Malpedia library", "url": "https://github.com/mlodic/ursnif_beacon_decryptor"}, {"source_name": "Malpedia", "description": "Reference found in the Malpedia library", "url": "https://kostas-ts.medium.com/ursnif-vs-italy-il-pdf-del-destino-5c83d6281072"}, {"source_name": "Malpedia", "description": "Reference found in the Malpedia library", "url": "https://lokalhost.pl/gozi_tree.txt"}, {"source_name": "Malpedia", "description": "Reference found in the Malpedia library", "url": "https://medium.com/csis-techblog/chapter-1-from-gozi-to-isfb-the-history-of-a-mythical-malware-family-82e592577fef"}, {"source_name": "Malpedia", "description": "Reference found in the Malpedia library", "url": "https://securelist.com/financial-cyberthreats-in-2020/101638/"}, {"source_name": "Malpedia", "description": "Reference found in the Malpedia library", "url": "https://securityintelligence.com/x-force/wailingcrab-malware-misues-mqtt-messaging-protocol/"}, {"source_name": "Malpedia", "description": "Reference found in the Malpedia library", "url": "https://therecord.media/gozi-malware-gang-member-arrested-in-colombia/"}, {"source_name": "Malpedia", "description": "Reference found in the Malpedia library", "url": "https://viuleeenz.github.io/posts/2023/03/dynamic-binary-instrumentation-for-malware-analysis/"}, {"source_name": "Malpedia", "description": "Reference found in the Malpedia library", "url": "https://viuleeenz.github.io/posts/2023/12/applied-emulation-decrypting-ursnif-strings-with-unicorn/"}, {"source_name": "Malpedia", "description": "Reference found in the Malpedia library", "url": "https://www.deepinstinct.com/2021/05/26/deep-dive-packing-software-cryptone/"}, {"source_name": "Malpedia", "description": "Reference found in the Malpedia library", "url": "https://www.f5.com/labs/articles/education/banking-trojans-a-reference-guide-to-the-malware-family-tree"}, {"source_name": "Malpedia", "description": "Reference found in the Malpedia library", "url": "https://www.microsoft.com/security/blog/2022/05/09/ransomware-as-a-service-understanding-the-cybercrime-gig-economy-and-how-to-protect-yourself"}, {"source_name": "Malpedia", "description": "Reference found in the Malpedia library", "url": "https://www.microsoft.com/security/blog/2022/05/09/ransomware-as-a-service-understanding-the-cybercrime-gig-economy-and-how-to-protect-yourself/"}, {"source_name": "Malpedia", "description": "Reference found in the Malpedia library", "url": "https://www.secureworks.com/research/gozi"}, {"source_name": "Malpedia", "description": "Reference found in the Malpedia library", "url": "https://www.secureworks.com/research/threat-profiles/gold-swathmore"}, {"source_name": "Malpedia", "description": "Reference found in the Malpedia library", "url": "https://www.trendmicro.com/content/dam/trendmicro/global/en/research/21/i/ssl-tls-technical-brief/ssl-tls-technical-brief.pdf"}, {"source_name": "Malpedia", "description": "Reference found in the Malpedia library", "url": "https://www.youtube.com/watch?v=BcFbkjUVc7o"}], "object_marking_refs": ["marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"], "nb_deps": 1, "x_opencti_stix_ids": null, "x_opencti_granted_refs": null, "x_opencti_workflow_id": null}'
//   },
//   {
//     'timestamp': '2024-10-11T20:10:06.786Z',
//     'message': '{\'name\': \'UNSUPPORTED_ERROR\', \'error_message\': \'Input resolve refs expect single value\'}',
//     'sequence': null,
//     'source': '{"type": "relationship", "spec_version": "2.1", "id": "relationship--799f653d-da5c-53ac-86d2-2046f1c93378", "created_by_ref": "identity--180d3ffd-a014-54ff-a817-211dddd29059", "created": "2024-10-11T17:19:43.689008Z", "modified": "2024-10-11T17:19:43.689008Z", "relationship_type": "originates-from", "source_ref": "intrusion-set--826cb3d9-0de3-5af7-9e95-f64fa12501a0", "target_ref": "location--efa1b9b0-dc59-5bad-baa2-4fc495e55fcc", "object_marking_refs": ["marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"], "nb_deps": 1, "x_opencti_granted_refs": null, "x_opencti_workflow_id": null}'
//   },
// ];

const ConnectorWorksComponent: FunctionComponent<ConnectorWorksComponentProps> = ({
  data,
  options,
  relay,
}) => {
  const works = data.works?.edges ?? [];
  const { t_i18n, nsdt } = useFormatter();
  const classes = useStyles();
  const [commit] = useApiMutation(connectorWorksWorkDeletionMutation);
  const [openDrawerErrors, setOpenDrawerErrors] = useState<boolean>(false);
  const [errors, setErrors] = useState<ParsedWorkMessage[]>([]);
  const [criticals, setCriticals] = useState<ParsedWorkMessage[]>([]);
  const [warnings, setWarnings] = useState<ParsedWorkMessage[]>([]);
  const [tabValue, setTabValue] = useState<string>('Critical');

  // Create custom error object from error because errors are in JSON
  const parseErrors = (errorsList: WorkMessages[]): ParsedWorkMessage[] => {
    // sort error by critical level
    const getLevel = (message: string) => {
      const type = JSON.parse(message.replace(/'/g, '"')).name;
      if (criticalErrorTypes.includes(type)) return 'Critical';
      if (warningErrorTypes.includes(type)) return 'Warning';
      return 'Unclassified';
    };
    return errorsList.map((error) => {
      // Try/Catch to prevent JSON.parse Exception
      try {
        const entityId = JSON.parse(error.source).name || JSON.parse(error.source).id;
        return {
          isParsed: true,
          level: getLevel(error.message),
          parsedError: {
            category: JSON.parse(error.message.replace(/'/g, '"')).name,
            message: JSON.parse(error.message.replace(/'/g, '"')).error_message,
            entity: {
              id: entityId,
              name: getMainRepresentative(JSON.parse(error.source), entityId),
              type: JSON.parse(error.source).type,
            },
          },
          rawError: error,
        };
      } catch (_) {
        return {
          isParsed: false,
          level: 'Unclassified',
          rawError: error,
        };
      }
    });
  };

  const handleOpenDrawerErrors = (errorsList: WorkMessages[]) => {
    setOpenDrawerErrors(true);
    // TODO : remove examples and use errorList
    // const parsedList = parseErrors([...errorsList, ...examples]);
    const parsedList = parseErrors(errorsList);
    setErrors(parsedList);
    const criticalErrors = parsedList.filter((error) => error.level === 'Critical');
    setCriticals(criticalErrors);
    const warningErrors = parsedList.filter((error) => error.level === 'Warning');
    setWarnings(warningErrors);
  };

  const handleCloseDrawerErrors = () => {
    setOpenDrawerErrors(false);
    setErrors([]);
  };

  const handleDeleteWork = (workId: string) => {
    commit({
      variables: {
        id: workId,
      },
      onCompleted: () => {
        MESSAGING$.notifySuccess('The work has been deleted');
      },
    });
  };

  useEffect(() => {
    const subscription = interval$.subscribe(() => {
      relay.refetch(options);
    });
    return () => subscription.unsubscribe();
  }, []);

  return (
    <div>
      {works.length === 0 && (
        <Paper
          classes={{ root: classes.paper }}
          variant="outlined"
        >
          <Typography align='center'>
            {t_i18n('No work')}
          </Typography>
        </Paper>
      )}
      {works.map((workEdge) => {
        const work = workEdge?.node;
        if (!work) return null;
        const { tracking } = work;
        return (
          <Paper
            key={work.id}
            classes={{ root: classes.paper }}
            variant="outlined"
          >
            <Grid container={true} spacing={3}>
              <Grid item xs={7}>
                <Grid container={true} spacing={1}>
                  <Grid item xs={8}>
                    <Typography variant="h3" gutterBottom={true}>
                      {t_i18n('Name')}
                    </Typography>
                    <Tooltip title={work.name}>
                      <Typography sx={{ overflowX: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'noWrap' }}>
                        {work.name}
                      </Typography>
                    </Tooltip>
                  </Grid>
                  <Grid item xs={4}>
                    <Typography variant="h3" gutterBottom={true}>
                      {t_i18n('Status')}
                    </Typography>
                    <TaskStatus status={work.status} label={t_i18n(work.status)} />
                  </Grid>
                  <Grid item xs={8}>
                    <Typography
                      variant="h3"
                      gutterBottom={true}
                      classes={{ root: classes.bottomTypo }}
                    >
                      {t_i18n('Work start time')}
                    </Typography>
                    {nsdt(work.received_time)}
                  </Grid>
                  <Grid item xs={4}>
                    <Typography
                      variant="h3"
                      gutterBottom={true}
                      classes={{ root: classes.bottomTypo }}
                    >
                      {t_i18n('Work end time')}
                    </Typography>
                    {work.completed_time ? nsdt(work.completed_time) : '-'}
                  </Grid>
                </Grid>
              </Grid>
              <Grid item xs={4}>
                <Grid container={true} spacing={3}>
                  <Grid item xs={6}>
                    <Typography variant="h3" gutterBottom={true}>
                      {t_i18n('Operations completed')}
                    </Typography>
                    <span className={classes.number}>
                      {work.status === 'wait'
                        ? '-'
                        : tracking?.import_processed_number ?? '-'}
                    </span>
                  </Grid>
                  <Grid item xs={6}>
                    <Typography variant="h3" gutterBottom={true}>
                      {t_i18n('Total number of operations')}
                    </Typography>
                    <span className={classes.number}>
                      {tracking?.import_expected_number ?? '-'}
                    </span>
                  </Grid>
                  <Grid item xs={11}>
                    <Typography variant="h3" gutterBottom={true}>
                      {t_i18n('Progress')}
                    </Typography>
                    <LinearProgress
                      classes={{ root: classes.progress }}
                      variant="determinate"
                      value={
                        tracking && !!tracking.import_expected_number && !!tracking.import_processed_number
                          ? Math.round((tracking.import_processed_number / tracking.import_expected_number) * 100)
                          : 0
                      }
                    />
                  </Grid>
                </Grid>
              </Grid>
              <Button
                classes={{ root: classes.errorButton }}
                variant="outlined"
                color={(work.errors ?? []).length === 0 ? 'success' : 'warning'}
                onClick={() => handleOpenDrawerErrors(work.errors ?? [] as any)}
                size="small"
              >
                {work.errors?.length} {t_i18n('errors')}
              </Button>
              <Security needs={[MODULES_MODMANAGE]}>
                <Button
                  variant="outlined"
                  classes={{ root: classes.deleteButton }}
                  onClick={() => handleDeleteWork(work.id)}
                  size="small"
                  startIcon={<Delete/>}
                >
                  {t_i18n('Delete')}
                </Button>
              </Security>
            </Grid>
          </Paper>
        );
      })}
      <Drawer
        title={t_i18n('Errors')}
        open={openDrawerErrors}
        onClose={handleCloseDrawerErrors}
      >
        <>
          <Alert severity="info">{t_i18n('This page lists only the first 100 errors returned by the connector to ensure readability and efficient troubleshooting')}</Alert>
          <Tabs value={tabValue} onChange={(_, newValue) => setTabValue(newValue)}>
            <Tab label={`${t_i18n('Critical')} (${criticals.length})`} value="Critical" />
            <Tab label={`${t_i18n('Warning')} (${warnings.length})`} value="Warning" />
            <Tab label={`${t_i18n('All')} (${errors.length})`} value="All" />
          </Tabs>
          <TableContainer component={Paper}>
            <Table aria-label="simple table">
              <TableHead>
                <TableRow>
                  <TableCell>{t_i18n('Timestamp')}</TableCell>
                  <TableCell>{t_i18n('Code')}</TableCell>
                  <TableCell>{t_i18n('Message')}</TableCell>
                  <TableCell>{t_i18n('Source')}</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {tabValue === 'Critical' && criticals.map((error) => (
                  <ConnectorWorksErrorLine key={error.rawError.timestamp} error={error} />
                ))}
                {tabValue === 'Warning' && warnings.map((error) => (
                  <ConnectorWorksErrorLine key={error.rawError.timestamp} error={error} />
                ))}
                {tabValue === 'All' && errors.map((error) => (
                  <ConnectorWorksErrorLine key={error.rawError.timestamp} error={error} />
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </>
      </Drawer>
    </div>
  );
};

export const connectorWorksQuery = graphql`
  query ConnectorWorksQuery(
    $count: Int
    $orderBy: WorksOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...ConnectorWorks_data
      @arguments(
        count: $count
        orderBy: $orderBy
        orderMode: $orderMode
        filters: $filters
      )
  }
`;

const ConnectorWorks = createRefetchContainer(
  ConnectorWorksComponent,
  {
    data: graphql`
      fragment ConnectorWorks_data on Query
      @argumentDefinitions(
        count: { type: "Int" }
        orderBy: { type: "WorksOrdering", defaultValue: timestamp }
        orderMode: { type: "OrderingMode", defaultValue: desc }
        filters: { type: "FilterGroup" }
      ) {
        works(
          first: $count
          orderBy: $orderBy
          orderMode: $orderMode
          filters: $filters
        ) {
          edges {
            node {
              id
              name
              user {
                name
              }
              timestamp
              status
              event_source_id
              received_time
              processed_time
              completed_time
              tracking {
                import_expected_number
                import_processed_number
              }
              messages {
                timestamp
                message
                sequence
                source
              }
              errors {
                timestamp
                message
                sequence
                source
              }
            }
          }
        }
      }
    `,
  },
  connectorWorksQuery,
);

export default ConnectorWorks;
