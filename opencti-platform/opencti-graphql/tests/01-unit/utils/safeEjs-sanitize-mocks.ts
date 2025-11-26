import type { StixCoreObject, StixId, StixRelationshipObject } from '../../../src/types/stix-2-1-common';

export interface NotificationData {
  notification_id: string
  instance: StixCoreObject | StixRelationshipObject | Partial<{ id: string | StixId | null }> | any
  type: string
  message: string
}

const DEFAULT_NOTIFICATION: NotificationData = {
  notification_id: 'default_notification_id',
  instance: {
    id: 'instanceId',
    name: 'Test Instance',
    // Fields required by HTML template
    report_types: ['threat-report'],
    labels: ['APT', 'Malware', 'Critical'],
    description: 'This is a detailed threat analysis report covering recent APT activities',
    // Field required by JSON template (Teams/Slack notifications)
    content: 'Critical security incident detected',
    // Additional fields for template-3
    published: '2024-01-15T10:00:00Z',
    external_references: [
      {
        source_name: 'MITRE ATT&CK',
        url: 'https://attack.mitre.org/techniques/T1566/',
        description: 'Phishing technique reference'
      },
      {
        source_name: 'Internal Report',
        description: 'Internal analysis document'
      }
    ]
  },
  type: 'create',
  message: '[TEST] Creates a report `Test Instance` with id: instanceId',
};

const DEFAULT_DIGEST: NotificationData[] = [
  {
    notification_id: 'default_notification_id',
    instance: {
      id: 'instanceId',
      name: 'Digest Item 1 - Critical Threat Report',
      report_types: ['threat-report'],
      labels: ['APT', 'Malware', 'Critical'],
      description: '## Executive Summary\n\nFirst item in digest - **threat analysis** report with *critical* findings.\n\n### Key Points\n- Advanced persistent threat detected\n- Multiple attack vectors identified\n- Immediate action required\n\n[View Full Report](https://opencti.io/report1)',
      content: 'Critical APT activity detected - multiple indicators observed',
      published: '2024-01-14T09:00:00Z',
      external_references: [
        {
          source_name: 'MITRE ATT&CK',
          url: 'https://attack.mitre.org/groups/G0007/',
          description: 'APT28 threat group reference'
        }
      ]
    },
    type: 'create',
    message: '[TEST] Creates a report `Digest Item 1 - Critical Threat Report` with id: instanceId',
  },
  {
    notification_id: 'default_notification_id_2',
    instance: {
      id: 'instanceId2',
      name: 'Digest Item 2 - Malware Analysis',
      report_types: ['malware-analysis'],
      labels: ['Malware', 'Trojan', 'High-Risk'],
      description: 'Second item in digest - **malware analysis** report identifying new trojan variant.\n\n- Hash: `d41d8cd98f00b204e9800998ecf8427e`\n- Family: Emotet\n- Risk Level: High',
      content: 'New malware variant identified - analysis complete',
      published: '2024-01-13T15:30:00Z',
      external_references: [
        {
          source_name: 'VirusTotal',
          url: 'https://www.virustotal.com/gui/file/d41d8cd98f00b204e9800998ecf8427e',
          description: 'VirusTotal analysis'
        }
      ]
    },
    type: 'update',
    message: '[TEST] Updates a malware `Digest Item 2 - Malware Analysis` with id: instanceId2',
  },
];

const DEFAULT_ACTIVITY = {
  notification_id: 'default_activity_id',
  instance: {
    id: 'activityId789',
    name: 'Suspicious Activity Report',
    entity_type: 'Report', // More common entity type for activity notifications
    report_types: ['activity-report'],
    labels: ['Activity', 'Update', 'Audit'],
    description: 'User activity audit trail - modification detected on critical report',
    content: 'Report properties have been modified by user admin',
    published: '2024-01-12T14:00:00Z',
    external_references: [],
    // Activity-specific field showing what changed
    input: [
      {
        key: 'name',
        value: [
          'Suspicious Activity Report' // New value
        ],
        old_value: [
          'Activity Report' // Previous value (useful for audit)
        ]
      },
      {
        key: 'confidence',
        value: [
          '85'
        ],
        old_value: [
          '75'
        ]
      }
    ]
  },
  type: 'update',
  message: '[TEST] User `admin` updates `name, confidence` for report `Suspicious Activity Report` with id: activityId789'
};

export const MOCK_NOTIFICATIONS: Record<string, NotificationData[]> = {
  default_notification: [DEFAULT_NOTIFICATION],
  default_digest: DEFAULT_DIGEST,
  default_activity: [DEFAULT_ACTIVITY],
};
