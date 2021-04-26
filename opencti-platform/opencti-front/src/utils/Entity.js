export const resolveLink = (type) => {
  switch (type) {
    case 'Attack-Pattern':
      return '/dashboard/arsenal/attack_patterns';
    case 'Campaign':
      return '/dashboard/threats/campaigns';
    case 'Note':
      return '/dashboard/analysis/notes';
    case 'Observed-Data':
      return '/dashboard/events/observed_data';
    case 'Opinion':
      return '/dashboard/analysis/opinions';
    case 'Report':
      return '/dashboard/analysis/reports';
    case 'Course-Of-Action':
      return '/dashboard/arsenal/courses_of_action';
    case 'Individual':
      return '/dashboard/entities/individuals';
    case 'Organization':
      return '/dashboard/entities/organizations';
    case 'Sector':
      return '/dashboard/entities/sectors';
    case 'Indicator':
      return '/dashboard/observations/indicators';
    case 'Infrastructure':
      return '/dashboard/observations/infrastructures';
    case 'Intrusion-Set':
      return '/dashboard/threats/intrusion_sets';
    case 'City':
      return '/dashboard/entities/cities';
    case 'Country':
      return '/dashboard/entities/countries';
    case 'Region':
      return '/dashboard/entities/regions';
    case 'Position':
      return '/dashboard/entities/positions';
    case 'Malware':
      return '/dashboard/arsenal/malwares';
    case 'Threat-Actor':
      return '/dashboard/threats/threat_actors';
    case 'Tool':
      return '/dashboard/arsenal/tools';
    case 'Vulnerability':
      return '/dashboard/arsenal/vulnerabilities';
    case 'Incident':
      return '/dashboard/events/incidents';
    case 'Artifact':
      return '/dashboard/observations/artifacts';
    case 'Stix-Cyber-Observable':
    case 'Autonomous-System':
    case 'Directory':
    case 'Domain-Name':
    case 'Email-Addr':
    case 'Email-Message':
    case 'Email-Mime-Part-Type':
    case 'StixFile':
    case 'X509-Certificate':
    case 'IPv4-Addr':
    case 'IPv6-Addr':
    case 'Mac-Addr':
    case 'Mutex':
    case 'Network-Traffic':
    case 'Process':
    case 'Software':
    case 'Url':
    case 'User-Account':
    case 'Windows-Registry-Key':
    case 'Windows-Registry-Value-Type':
    case 'X509-V3-Extensions-Type':
    case 'X-OpenCTI-Cryptographic-Key':
    case 'X-OpenCTI-Cryptocurrency-Wallet':
    case 'X-OpenCTI-Hostname':
    case 'X-OpenCTI-Text':
    case 'X-OpenCTI-User-Agent':
      return '/dashboard/observations/observables';
    default:
      return null;
  }
};

export const openVocabularies = {
  'malware-type-ov': [
    {
      key: 'adware',
      description:
        'Any software that is funded by advertising. Adware may also gather sensitive user information from a system.',
    },
    {
      key: 'backdoor',
      description:
        'A malicious program that allows an attacker to perform actions on a remote system, such as transferring files, acquiring passwords, or executing arbitrary commands [NIST800-83].',
    },
    {
      key: 'bot',
      description:
        'A program that resides on an infected system, communicating with and forming part of a botnet. The bot may be implanted by a worm or Trojan, which opens a backdoor. The bot then monitors the backdoor for further instructions.',
    },
    {
      key: 'bootkit',
      description:
        'A malicious program which targets the Master Boot Record of the target computer.',
    },
    {
      key: 'ddos',
      description:
        'A program that is used to perform a distributed denial of service attack.',
    },
    {
      key: 'downloader',
      description:
        'A small trojan file programmed to download and execute other files, usually more complex malware.',
    },
    {
      key: 'dropper',
      description:
        'A type of trojan that deposits an enclosed payload (generally, other malware) onto the target computer.',
    },
    {
      key: 'exploit-kit',
      description: 'A software toolkit to target common vulnerabilities.',
    },
    {
      key: 'keylogger',
      description:
        'A type of malware that surreptitiously monitors keystrokes and either records them for later retrieval or sends them back to a central collection point.',
    },
    {
      key: ' ransomware',
      description:
        "A type of malware that encrypts files on a victim's system, demanding payment of ransom in return for the access codes required to unlock files.",
    },
    {
      key: 'remote-access-trojan',
      description:
        'A remote access trojan program (or RAT), is a trojan horse capable of controlling a machine through commands issued by a remote attacker.',
    },
    {
      key: 'resource-exploitation',
      description:
        "A type of malware that steals a system's resources (e.g., CPU cycles), such as a malicious bitcoin miner.",
    },
    {
      key: 'rogue-security-software',
      description:
        'A fake security product that demands money to clean phony infections.',
    },
    {
      key: 'rootkit',
      description:
        'A type of malware that hides its files or processes from normal methods of monitoring in order to conceal its presence and activities. Rootkits can operate at a number of levels, from the application level — simply replacing or adjusting the settings of system software to prevent the display of certain information — through hooking certain functions or inserting modules or drivers into the operating system kernel, to the deeper level of firmware or virtualization rootkits, which are activated before the operating system and thus even harder to detect while the system is running.',
    },
    {
      key: 'screen-capture',
      description:
        'A type of malware used to capture images from the target systems screen, used for exfiltration and command and control.',
    },
    {
      key: 'spyware',
      description:
        "Software that gathers information on a user's system without their knowledge and sends it to another party. Spyware is generally used to track activities for the purpose of delivering advertising.",
    },
    {
      key: 'trojan',
      description:
        'Any malicious computer program which is used to hack into a computer by misleading users of its true intent.',
    },
    {
      key: 'unknown',
      description:
        'There is not enough information available to determine the type of malware.',
    },
    {
      key: 'virus',
      description:
        'A malicious computer program that replicates by reproducing itself or infecting other programs by modifying them.',
    },
    {
      key: 'webshell',
      description:
        'A malicious script used by an attacker with the intent to escalate and maintain persistent access on an already compromised web application.',
    },
    {
      key: 'wiper',
      description:
        'A piece of malware whose primary aim is to delete files or entire disks on a machine.',
    },
    {
      key: 'worm',
      description:
        'A self-replicating, self-contained program that usually executes itself without user intervention.',
    },
  ],
  'processor-architecture-ov': [
    { key: 'alpha', description: 'Specifies the Alpha architecture.' },
    {
      key: 'arm',
      description: 'Specifies the ARM architecture.',
    },
    {
      key: 'ia-64',
      description: 'Specifies the 64-bit IA (Itanium) architecture.',
    },
    {
      key: 'mips',
      description: 'Specifies the MIPS architecture.',
    },
    {
      key: 'powerpc',
      description: 'Specifies the PowerPC architecture.',
    },
    {
      key: 'sparc',
      description: 'Specifies the SPARC architecture.',
    },
    {
      key: 'x86',
      description: 'Specifies the 32-bit x86 architecture.',
    },
    {
      key: 'x86-64',
      description: 'Specifies the 64-bit x86 architecture.',
    },
  ],
  'implementation-language-ov': [
    {
      key: 'applescript',
      description: 'Specifies the AppleScript programming language.',
    },
    {
      key: 'bash',
      description: 'Specifies the Bash programming language.',
    },
    {
      key: 'c',
      description: 'Specifies the C programming language.',
    },
    {
      key: 'c++',
      description: 'Specifies the C++ programming language.',
    },
    {
      key: 'c#',
      description: 'Specifies the C# programming language.',
    },
    {
      key: 'go',
      description:
        'Specifies the Go (sometimes referred to as golang) programming language.',
    },
    {
      key: 'java',
      description: 'Specifies the JAVA programming language.',
    },
    {
      key: 'javascript',
      description: 'Specifies the JavaScript programming language.',
    },
    {
      key: 'lua',
      description: 'Specifies the Lua programming language.',
    },
    {
      key: 'objective-c',
      description: 'Specifies the Objective-C programming language.',
    },
    {
      key: 'perl',
      description: 'Specifies the Perl programming language.',
    },
    {
      key: 'php',
      description: 'Specifies the PHP programming language.',
    },
    {
      key: 'powershell',
      description: 'Specifies the Windows Powershell programming language.',
    },
    {
      key: 'python',
      description: 'Specifies the Python programming language.',
    },
    {
      key: 'ruby',
      description: 'Specifies the Ruby programming language.',
    },
    {
      key: 'scala',
      description: 'Specifies the Scala programming language.',
    },
    {
      key: 'swift',
      description: 'Specifies the Swift programming language.',
    },
    {
      key: 'typescript',
      description: 'Specifies the TypeScript programming language.',
    },
    {
      key: 'visual-basic',
      description: 'Specifies the Visual Basic programming language.',
    },
    {
      key: 'x86-32',
      description: 'Specifies the x86 32-bit Assembly programming language.',
    },
    {
      key: 'x86-64',
      description: 'Specifies the x86 64-bit Assembly programming language.',
    },
  ],
  'malware-capabilities-ov': [
    {
      key: 'accesses-remote-machines',
      description:
        'Indicates that the malware instance or family is able to access one or more remote machines.',
    },
    {
      key: 'anti-debugging',
      description:
        'Indicates that the malware instance or family is able to prevent itself from being debugged and/or from being run in a debugger or is able to make debugging more difficult.',
    },
    {
      key: 'anti-disassembly',
      description:
        'Indicates that the malware instance or family is able to prevent itself from being disassembled or make disassembly more difficult.',
    },

    {
      key: 'anti-emulation',
      description:
        'Indicates that the malware instance or family is able to prevent its execution inside of an emulator or is able to make emulation more difficult.',
    },
    {
      key: 'anti-memory-forensics',
      description:
        'Indicates that the malware instance or family is able to prevent or make memory forensics more difficult.',
    },
    {
      key: 'anti-sandbox',
      description:
        'Indicates that the malware instance or family is able to prevent sandbox-based behavioral analysis or make it more difficult.',
    },
    {
      key: 'anti-vm',
      description:
        'Indicates that the malware instance or family is able to prevent virtual machine (VM) based behavioral analysis or make it more difficult.',
    },
    {
      key: 'captures-input-peripherals',
      description:
        "Indicates that the malware instance or family is able to capture data from a system's input peripheral devices, such as a keyboard or mouse. This includes things like keylogging.",
    },
    {
      key: 'captures-output-peripherals',
      description:
        "Indicates that the malware instance or family captures data sent to a system's output peripherals, such as a display. Examples include things like screen scraping.",
    },
    {
      key: 'captures-system-state-data',
      description:
        "Indicates that the malware instance or family is able to capture information about a system's state (e.g., data currently in its RAM).",
    },
    {
      key: 'cleans-traces-of-infection',
      description:
        'Indicates that the malware instance or family is able to clean traces of its infection (e.g., file system artifacts) from a system.',
    },
    {
      key: 'commits-fraud',
      description:
        'Indicates that the malware instance or family commits fraud, such as click fraud (for example).',
    },
    {
      key: 'communicates-with-c2',
      description:
        'Indicates that the malware instance or family is able to communicate (i.e., send or receive data) with a command and control (C2) server.',
    },
    {
      key: 'compromises-data-availability',
      description:
        'Indicates that the malware instance or family is able to compromise the availability of data on the local system on which it is executing and/or one or more remote systems. For example, encrypting data on disk, as done by ransomware.',
    },
    {
      key: 'compromises-data-integrity',
      description:
        'Indicates that the malware instance or family is able to compromise the integrity of some data that resides on (e.g., in the case of files) or is received/transmitted (e.g., in the case of network traffic) by the system on which it is executing.',
    },
    {
      key: 'compromises-system-availability',
      description:
        'Indicates that the malware instance or family is able to consume system resources for its malicious purposes, such as password cracking or participating in a DDoS botnet, thereby compromising the availability of the local system and/or one or more remote systems.',
    },
    {
      key: 'controls-local-machine',
      description:
        'Indicates that the malware instance or family is able to control the machine on which it is executing (e.g., RATs).',
    },
    {
      key: 'degrades-security-software',
      description:
        'Indicates that the malware instance or family is able to bypass or disable security programs or operating system security features on a system (including mobile devices), either by stopping them from executing or by making changes to their code or configuration parameters. For example, malware that blocks the local machine from accessing the websites of security vendors.',
    },
    {
      key: 'degrades-system-updates',
      description:
        'Indicates that the malware instance or family is able to disable the downloading and installation of system updates and patches.',
    },
    {
      key: 'determines-c2-server',
      description:
        'Indicates that the malware instance or family is able to identify one or more command and control (C2) servers with which to communicate (e.g., DGA).',
    },
    {
      key: 'emails-spam',
      description:
        'Indicates that the malware instance or family is able to send spam email messages.',
    },
    {
      key: 'escalates-privileges',
      description:
        'Indicates that the malware instance or family is able to escalate the privileges under which it is executing.',
    },
    {
      key: 'evades-av',
      description:
        'Indicates that the malware instance or family is able to evade detection by antivirus tools.',
    },
    {
      key: 'exfiltrates-data',
      description:
        'Indicates that the malware instance or family is able to gather, prepare, (possibly obfuscate) data and transmit it to exfiltration points.',
    },
    {
      key: 'fingerprints-host',
      description:
        'Indicates that the malware instance or family is able to fingerprint or probe the configuration of the host system on which it is executing for the purpose of altering its behavior based on this environment.',
    },
    {
      key: 'hides-artifacts',
      description:
        'Indicates that the malware instance or family is able to hide its artifacts, such as files and open ports.',
    },
    {
      key: 'hides-executing-code',
      description:
        'Indicates that the malware instance or family is able to hide its code by compromising the bootloader, kernel modules, hypervisor, etc.',
    },
    {
      key: 'infects-files',
      description:
        'Indicates that the malware instance or family is able to infect one or more files on the system on which it executes. For example, malware which injects a malicious payload into all PDFs on a host as a means of propagation.',
    },
    {
      key: 'infects-remote-machines',
      description:
        'Indicates that the malware instance or family is able to self-propagate to a remote machine or infect a remote machine with malware that is different than itself.',
    },
    {
      key: 'installs-other-components',
      description:
        'Indicates that the malware instance or family is able to install additional components. This encompasses the dropping/downloading of other malicious components such as libraries, other malware, and tools.',
    },
    {
      key: 'persists-after-system-reboot',
      description:
        'Indicates that the malware instance or family is able to continue executing after the reboot of the system on which it is resident.',
    },
    {
      key: 'prevents-artifact-access',
      description:
        'Indicates that the malware instance or family is able to prevent its artifacts (e.g., files, registry keys, etc.) from being accessed.',
    },
    {
      key: 'prevents-artifact-deletion',
      description:
        'Indicates that the malware instance or family is able to prevent its artifacts (e.g., files, registry keys, etc.) from being deleted.',
    },
    {
      key: 'probes-network-environment',
      description:
        'Indicates that the malware instance or family is able to probe the properties of its network environment, e.g. to determine whether it funnels traffic through a proxy.',
    },
    {
      key: 'self-modifies',
      description:
        'Indicates that the malware instance or family is able to modify itself.',
    },
    {
      key: 'steals-authentication-credentials',
      description:
        'Indicates that the malware instance is able to steal authentication credentials.',
    },
    {
      key: 'violates-system-operational-integrity',
      description:
        'Indicates that the malware instance or family is able to compromise the operational integrity of the system on which it is executing and/or one or more remote systems, e.g., by causing them to operate beyond their set of specified operational parameters. For example, malware that causes the CPU fan on the machine that it is executing to spin at a higher than normal speed.',
    },
  ],
  'attack-resource-level-ov': [
    {
      key: 'individual',
      description:
        'Resources limited to the average individual; Threat Actor acts independently.',
    },
    {
      key: 'club',
      description:
        'Members interact on a social and volunteer basis, often with little personal interest in the specific target. An example might be a core group of unrelated activists who regularly exchange tips on a particular blog. Group persists long term.',
    },
    {
      key: 'contest',
      description:
        'A short-lived and perhaps anonymous interaction that concludes when the participants have achieved a single goal. For example, people who break into systems just for thrills or prestige may hold a contest to see who can break into a specific target first. It also includes announced "operations" to achieve a specific goal, such as the original "OpIsrael" call for volunteers to disrupt all of Israel\'s Internet functions for a day.',
    },
    {
      key: 'team',
      description:
        'A formally organized group with a leader, typically motivated by a specific goal and organized around that goal. Group persists long term and typically operates within a single geography.',
    },
    {
      key: 'organization',
      description:
        'Larger and better resourced than a team; typically, a company or crime syndicate. Usually operates in multiple geographic areas and persists long term.',
    },
    {
      key: 'government',
      description:
        'Controls public assets and functions within a jurisdiction; very well resourced and persists long term.',
    },
  ],
  'attack-motivation-ov': [
    {
      key: 'accidental',
      description:
        'A non-hostile actor whose benevolent or harmless intent inadvertently causes harm. For example, a well-meaning and dedicated employee who through distraction or poor training unintentionally causes harm to his or her organization.',
    },
    {
      key: 'coercion',
      description:
        "Being forced to act on someone else's behalf. Adversaries who are motivated by coercion are often forced through intimidation or blackmail to act illegally for someone else’s benefit. Unlike the other motivations, a coerced person does not act for personal gain, but out of fear of incurring a loss.",
    },
    {
      key: 'dominance',
      description:
        'A desire to assert superiority over someone or something else. Adversaries who are seeking dominance over a target are focused on using their power to force their target into submission or irrelevance. Dominance may be found with ideology in some state-sponsored attacks and with notoriety in some cyber vandalism-based attacks.',
    },
    {
      key: 'ideology',
      description:
        'A passion to express a set of ideas, beliefs, and values that may shape and drive harmful and illegal acts. Adversaries who act for ideological reasons (e.g., political, religious, human rights, environmental, desire to cause chaos/anarchy, etc.) are not usually motivated primarily by the desire for profit; they are acting on their own sense of morality, justice, or political loyalty. For example, an activist group may sabotage a company’s equipment because they believe the company is harming the environment.',
    },
    {
      key: 'notoriety',
      description:
        'Seeking prestige or to become well known through some activity. Adversaries motivated by notoriety are often seeking either personal validation or respect within a community and staying covert is not a priority. In fact, one of the main goals is to garner the respect of their target audience.',
    },
    {
      key: 'organizational-gain',
      description:
        'Seeking advantage over a competing organization, including a military organization. Adversaries motivated by increased profit or other gains through an unfairly obtained competitive advantage are often seeking theft of intellectual property, business processes, or supply chain agreements and thus accelerating their position in a market or capability.',
    },
    {
      key: 'personal-gain',
      description:
        'The desire to improve one’s own financial status. Adversaries motivated by a selfish desire for personal gain are often out for gains that come from financial fraud, hacking for hire, or intellectual property theft. While a Threat Actor or Intrusion Set may be seeking personal gain, this does not mean they are acting alone. Individuals can band together solely to maximize their own personal profits.',
    },

    {
      key: 'personal-satisfaction',
      description:
        'A desire to satisfy a strictly personal goal, including curiosity, thrill-seeking, amusement, etc. Threat Actors or Intrusion Set driven by personal satisfaction may incidentally receive some other gain from their actions, such as a profit, but their primary motivation is to gratify a personal, emotional need. Individuals can band together with others toward a mutual, but not necessarily organizational, objective.',
    },
    {
      key: 'revenge',
      description:
        'A desire to avenge perceived wrongs through harmful actions such as sabotage, violence, theft, fraud, or embarrassing certain individuals or the organization. A disgruntled Threat Actor or Intrusion Set seeking revenge can include current or former employees, who may have extensive knowledge to leverage when conducting attacks. Individuals can band together with others if the individual believes that doing so will enable them to cause more harm.',
    },
    {
      key: 'unpredictable',
      description:
        'Acting without identifiable reason or purpose and creating unpredictable events. Unpredictable is not a miscellaneous or default category. Unpredictable means a truly random and likely bizarre event, which seems to have no logical purpose to the victims.',
    },
  ],
};
