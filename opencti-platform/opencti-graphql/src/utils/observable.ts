import {
  ENTITY_AUTONOMOUS_SYSTEM,
  ENTITY_BANK_ACCOUNT,
  ENTITY_CREDENTIAL,
  ENTITY_CRYPTOGRAPHIC_KEY,
  ENTITY_CRYPTOGRAPHIC_WALLET,
  ENTITY_DIRECTORY,
  ENTITY_DOMAIN_NAME,
  ENTITY_EMAIL_ADDR,
  ENTITY_HASHED_OBSERVABLE_ARTIFACT,
  ENTITY_HASHED_OBSERVABLE_STIX_FILE,
  ENTITY_HASHED_OBSERVABLE_X509_CERTIFICATE,
  ENTITY_HOSTNAME,
  ENTITY_IPV4_ADDR,
  ENTITY_IPV6_ADDR,
  ENTITY_MAC_ADDR,
  ENTITY_MUTEX,
  ENTITY_NETWORK_TRAFFIC,
  ENTITY_PAYMENT_CARD,
  ENTITY_PHONE_NUMBER,
  ENTITY_PROCESS,
  ENTITY_SOFTWARE,
  ENTITY_TEXT,
  ENTITY_TRACKING_NUMBER,
  ENTITY_URL,
  ENTITY_USER_ACCOUNT,
  ENTITY_USER_AGENT,
  ENTITY_WINDOWS_REGISTRY_KEY,
} from '../schema/stixCyberObservable';

interface ObservablePattern {
  type: string;
  patterns: RegExp[];
  priority?: number; // Higher priority patterns are tested first
}

/**
 * Detects the type of STIX cyber observable from a given text value.
 * Falls back to 'Text' type if no specific type can be determined.
 */
export const detectObservableType = (value: string): string => {
  if (!value || typeof value !== 'string') {
    return ENTITY_TEXT;
  }

  const trimmedValue = value.trim();

  // Define patterns for each observable type with priority
  const observablePatterns: ObservablePattern[] = [
    // Network observables - High priority
    {
      type: ENTITY_IPV4_ADDR,
      patterns: [
        /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/,
        /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/\d{1,2}$/, // CIDR notation
      ],
      priority: 10
    },
    {
      type: ENTITY_IPV6_ADDR,
      patterns: [
        /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/,
        /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4})\/\d{1,3}$/, // CIDR notation
      ],
      priority: 10
    },
    {
      type: ENTITY_MAC_ADDR,
      patterns: [
        /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/,
        /^([0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}$/,
      ],
      priority: 10
    },
    {
      type: ENTITY_URL,
      patterns: [
        /^(https?|ftp):\/\/[^\s/$.?#].[^\s]*$/i,
        /^(https?|ftp):\/\/(www\.)?[-a-zA-Z0-9@:%._+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_+.~#?&/=]*)$/i,
      ],
      priority: 9
    },

    // Email and communication
    {
      type: ENTITY_EMAIL_ADDR,
      patterns: [
        /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/,
      ],
      priority: 9
    },
    {
      type: ENTITY_PHONE_NUMBER,
      patterns: [
        /^[+]?[(]?[0-9]{1,4}[)]?[-\s.]?[(]?[0-9]{1,4}[)]?[-\s.]?[0-9]{1,5}[-\s.]?[0-9]{1,5}$/,
        /^\+?[1-9]\d{1,14}$/, // E.164 format
        /^(\+\d{1,3}[-.\s]?)?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}$/,
      ],
      priority: 8
    },

    // Domain and hostname
    {
      type: ENTITY_DOMAIN_NAME,
      patterns: [
        /^(?!:\/\/)([a-zA-Z0-9-_]+\.)*[a-zA-Z0-9][a-zA-Z0-9-_]+\.[a-zA-Z]{2,11}?$/,
        /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i,
      ],
      priority: 7
    },
    {
      type: ENTITY_HOSTNAME,
      patterns: [
        /^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9-]*[A-Za-z0-9])$/,
      ],
      priority: 6
    },

    // File system
    {
      type: ENTITY_DIRECTORY,
      patterns: [
        /^([a-zA-Z]:)?[/\\](?:[^/\\:*?"<>|]+[/\\])*[^/\\:*?"<>|]*$/, // Windows path
        /^\/(?:[^/]+\/)*[^/]*$/, // Unix path
        /^[a-zA-Z]:\\(?:[^\\/:*?"<>|]+\\)*[^\\/:*?"<>|]*$/, // Windows with backslashes
      ],
      priority: 7
    },
    {
      type: ENTITY_HASHED_OBSERVABLE_STIX_FILE,
      patterns: [
        /^([a-zA-Z]:)?[/\\](?:[^/\\:*?"<>|]+[/\\])*[^/\\:*?"<>|]+\.[a-zA-Z0-9]+$/, // File with extension
        /^\/(?:[^/]+\/)*[^/]+\.[a-zA-Z0-9]+$/, // Unix file with extension
        /\.(exe|dll|pdf|doc|docx|xls|xlsx|zip|tar|gz|jpg|jpeg|png|gif|mp4|mp3|txt|log|dat|bin|iso|dmg|pkg|deb|rpm)$/i,
      ],
      priority: 8
    },

    // Hashes and cryptographic
    {
      type: ENTITY_HASHED_OBSERVABLE_ARTIFACT,
      patterns: [
        /^[a-fA-F0-9]{32}$/, // MD5
        /^[a-fA-F0-9]{40}$/, // SHA-1
        /^[a-fA-F0-9]{64}$/, // SHA-256
        /^[a-fA-F0-9]{128}$/, // SHA-512
      ],
      priority: 9
    },
    {
      type: ENTITY_CRYPTOGRAPHIC_KEY,
      patterns: [
        /^-----BEGIN (RSA |DSA |EC |OPENSSH |PGP |)?(PUBLIC|PRIVATE) KEY-----/m,
        /^ssh-(rsa|dss|ed25519|ecdsa) [A-Za-z0-9+/]+[=]{0,2}(\s|$)/,
      ],
      priority: 8
    },
    {
      type: ENTITY_CRYPTOGRAPHIC_WALLET,
      patterns: [
        /^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/, // Bitcoin address
        /^0x[a-fA-F0-9]{40}$/, // Ethereum address
        /^[LM3][a-km-zA-HJ-NP-Z1-9]{25,34}$/, // Litecoin address
        /^bc1[a-z0-9]{39,59}$/, // Bitcoin Bech32 address
      ],
      priority: 8
    },

    // System and process
    {
      type: ENTITY_PROCESS,
      patterns: [
        /^[a-zA-Z0-9_-]+\.(exe|dll|so|app|bat|sh|cmd|ps1)$/i,
        /^(pid:|process:|PID:)\s*\d+$/i,
        /^\d+\s+[a-zA-Z0-9_-]+(\.(exe|dll|so))?$/i, // PID followed by process name
      ],
      priority: 6
    },
    {
      type: ENTITY_MUTEX,
      patterns: [
        /^(Global\\|Local\\|Session\\)?[a-zA-Z0-9_-]+$/,
        /^\\BaseNamedObjects\\[a-zA-Z0-9_-]+$/,
      ],
      priority: 5
    },
    {
      type: ENTITY_SOFTWARE,
      patterns: [
        /^[a-zA-Z0-9\s._-]+\s+v?\d+(\.\d+)*$/i, // Software with version
        /^[a-zA-Z0-9\s._-]+\s+\d+(\.\d+)+(\.\d+)?$/i, // Name with version numbers
      ],
      priority: 5
    },

    // Windows Registry
    {
      type: ENTITY_WINDOWS_REGISTRY_KEY,
      patterns: [
        /^(HKEY_|HKLM\\|HKCU\\|HKU\\|HKCR\\|HKCC\\)/i,
        /^(HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_USERS|HKEY_CLASSES_ROOT|HKEY_CURRENT_CONFIG)(\\[^\\]+)*$/i,
      ],
      priority: 8
    },

    // User and credentials
    {
      type: ENTITY_USER_ACCOUNT,
      patterns: [
        /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+$/, // username@domain
        /^(admin|administrator|root|user|guest|test)[0-9]*$/i,
        /^[a-zA-Z0-9_-]{3,32}$/, // Simple username
      ],
      priority: 4
    },
    {
      type: ENTITY_CREDENTIAL,
      patterns: [
        /^[a-zA-Z0-9._-]+:[a-zA-Z0-9!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]+$/, // username:password format
      ],
      priority: 7
    },

    // Financial
    {
      type: ENTITY_PAYMENT_CARD,
      patterns: [
        /^[0-9]{13,19}$/, // Credit card number (basic)
        /^4[0-9]{12}(?:[0-9]{3})?$/, // Visa
        /^5[1-5][0-9]{14}$/, // Mastercard
        /^3[47][0-9]{13}$/, // American Express
        /^6(?:011|5[0-9]{2})[0-9]{12}$/, // Discover
      ],
      priority: 7
    },
    {
      type: ENTITY_BANK_ACCOUNT,
      patterns: [
        /^[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}$/, // IBAN format
        /^[0-9]{8,12}$/, // Basic account number
        /^\d{3}-\d{2}-\d{4}$/, // US SSN format (sometimes used for banking)
      ],
      priority: 6
    },

    // Tracking
    {
      type: ENTITY_TRACKING_NUMBER,
      patterns: [
        /^1Z[0-9A-Z]{16}$/i, // UPS
        /^[0-9]{20,22}$/, // USPS
        /^[0-9]{12,14}$/, // FedEx
        /^[A-Z]{2}[0-9]{9}[A-Z]{2}$/i, // International shipping
      ],
      priority: 6
    },

    // Network Traffic
    {
      type: ENTITY_NETWORK_TRAFFIC,
      patterns: [
        /^(tcp|udp|icmp|http|https|ftp|ssh|telnet|smtp|pop3|imap):\/?\/?/i,
        /^port:\s*\d{1,5}$/i,
        /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}$/, // IP:Port
      ],
      priority: 7
    },

    // User Agent
    {
      type: ENTITY_USER_AGENT,
      patterns: [
        /^Mozilla\/[0-9.]+\s+\([^)]+\)/,
        /^(Chrome|Firefox|Safari|Edge|Opera)\/[0-9.]+/i,
        /(Chrome|Firefox|Safari|Edge|Opera|Mozilla|AppleWebKit|Gecko|Trident)/i,
      ],
      priority: 6
    },

    // Autonomous System
    {
      type: ENTITY_AUTONOMOUS_SYSTEM,
      patterns: [
        /^AS\d{1,10}$/i,
        /^ASN?\s*\d{1,10}$/i,
      ],
      priority: 8
    },

    // Certificate
    {
      type: ENTITY_HASHED_OBSERVABLE_X509_CERTIFICATE,
      patterns: [
        /^-----BEGIN CERTIFICATE-----/m,
        /^-----BEGIN X509 CRL-----/m,
        /^MII[A-Za-z0-9+/]+={0,2}$/, // Base64 encoded certificate
      ],
      priority: 8
    },
  ];

  // Sort patterns by priority (higher priority first)
  const sortedPatterns = observablePatterns.sort((a, b) => (b.priority || 0) - (a.priority || 0));

  // Test each pattern against the value
  const matchedPattern = sortedPatterns.find((observablePattern) => observablePattern.patterns.some((pattern) => pattern.test(trimmedValue)));
  if (matchedPattern) {
    return matchedPattern.type;
  }

  // Default fallback to Text type
  return ENTITY_TEXT;
};

/**
 * Detects multiple observable types from an array of values.
 * Returns a map of values to their detected types.
 */
export const detectObservableTypes = (values: string[]): Map<string, string> => {
  const result = new Map<string, string>();
  values.forEach((value) => {
    result.set(value, detectObservableType(value));
  });
  return result;
};

/**
 * Groups values by their detected observable type.
 */
export const groupByObservableType = (values: string[]): Record<string, string[]> => {
  const grouped: Record<string, string[]> = {};

  values.forEach((value) => {
    const type = detectObservableType(value);
    if (!grouped[type]) {
      grouped[type] = [];
    }
    grouped[type].push(value);
  });

  return grouped;
};
