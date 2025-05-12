import { CommonColors, PaletteColorOptions, PaletteMode, PaletteOptions, TypeBackground, TypeText } from '@mui/material/styles/createPalette';
import { Theme as MuiTheme, ThemeOptions } from '@mui/material/styles/createTheme';

declare module '@mui/material/IconButton' {
  interface IconButtonPropsColorOverrides {
    ee: true
    dangerZone: true
  }
}

declare module '@mui/material/Button' {
  interface ButtonPropsColorOverrides {
    ee: true
    pagination: true
  }
}

declare module '@mui/material/ButtonGroup' {
  interface ButtonGroupPropsColorOverrides {
    pagination: true
  }
}

declare module '@mui/material/SvgIcon' {
  interface SvgIconPropsColorOverrides {
    ee: true
  }
}

declare module '@mui/material/Fab' {
  interface FabPropsColorOverrides {
    dangerZone: true
  }
}

declare module '@mui/material/Alert' {
  interface AlertPropsColorOverrides {
    dangerZone: true
  }
}

interface ExtendedColor extends PaletteColorOptions {
  main: string
  dark: string
  light: string
  palette: ExtendedPaletteOptions
  text: Partial<TypeText>
  mode: PaletteMode
  background: string
  lightBackground: string
  contrastText: string
}

interface ExtendedBackground extends TypeBackground {
  nav: string
  accent: string
  shadow: string
}

interface ExtendedPaletteOptions extends PaletteOptions {
  common: Partial<CommonColors & { grey: string, lightGrey: string }>
  background: Partial<ExtendedBackground>
  border: {
    primary: string
    secondary: string
    pagination: string
    lightBackground?: string
  }
  dangerZone: Partial<ExtendedColor>
  primary: Partial<ExtendedColor>
  error: Partial<ExtendedColor>
  warn: Partial<ExtendedColor>
  success: Partial<ExtendedColor>
  chip: Partial<ExtendedColor>
  pagination: Partial<ExtendedColor>
  ee: Partial<ExtendedColor>
  ai: Partial<ExtendedColor>
  gradient: Partial<ExtendedColor>
  secondary: Partial<ExtendedColor>
  mode: PaletteMode
  entities: {
    'Attack-Pattern': string
    'Case-Incident': string
    'Case-Rfi': string
    'Case-Rft': string
    'Case-Feedback': string
    Task: string
    Campaign: string
    Note: string
    'Observed-Data': string
    Opinion: string
    Report: string
    Grouping: string
    'Course-Of-Action': string
    Individual: string
    User: string
    Group: string
    Capability: string
    Organization: string
    Sector: string
    System: string
    Event: string
    Indicator: string
    Infrastructure: string
    'Intrusion-Set': string
    City: string
    Country: string
    Region: string
    'Administrative-Area': string
    Position: string
    Malware: string
    'Malware-Analysis': string
    'Threat-Actor-Group': string
    'Threat-Actor-Individual': string
    Tool: string
    Channel: string
    Narrative: string
    Language: string
    Vulnerability: string
    Incident: string
    Dashboard: string
    Investigation: string
    Session: string
    Artifact: string
    'Stix-Cyber-Observable': string
    'Autonomous-System': string
    Directory: string
    'Domain-Name': string
    'Email-Addr': string
    'Email-Message': string
    'Email-Mime-Part-Type': string
    StixFile: string
    'X509-Certificate': string
    'IPv4-Addr': string
    'IPv6-Addr': string
    'Mac-Addr': string
    Mutex: string
    'Network-Traffic': string
    Process: string
    Software: string
    Url: string
    'User-Account': string
    'Windows-Registry-Key': string
    'Windows-Registry-Value-Type': string
    'Cryptographic-Key': string
    'Cryptocurrency-Wallet': string
    Text: string
    'User-Agent': string
    'Bank-Account': string
    Credential: string
    'Tracking-Number': string
    'Phone-Number': string
    'Payment-Card': string
    'Media-Content': string
    Persona: string
  }
  relationships: {
    'Stix-Core-Relationship': string
    Relationship: string
    'stix-core-relationship': string
    'targets': string
    'uses': string
    'located-at': string
    'related-to': string
    'mitigates': string
    'impersonates': string
    'indicates': string
    'comes-after': string
    'attributed-to': string
    'variant-of': string
    'part-of': string
    'employed-by': string
    'resides-in': string
    'citizen-of': string
    'national-of': string
    'drops': string
    'delivers': string
    'compromises': string
    'belongs-to': string
    'based-on': string
    'communicates-with': string
    'amplifies': string
    'analyses-of': string
    'authored-by': string
    'beacons-to': string
    'characterizes': string
    'consists-of': string
    'controls': string
    'cooperates-with': string
    'derived-from': string
    'downloads': string
    'has': string
    'bcc': string
    'cc': string
    'obs_belongs-to': string
    'owns': string
    'dst': string
    'from': string
    'hosts': string
    'image': string
    'publishes': string
    'duplicate-of': string
    'obs_content': string
    'service-dll': string
    'dynamic-analyses-of': string
    'contains': string
    'exfiltrates-to': string
    'exploits': string
    'investigates': string
    'originates-from': string
    'participates-in': string
    'body-multipart': string
    'body-raw': string
    'child': string
    'creator-user': string
    'detects': string
    'dst-payload': string
    'encapsulated-by': string
    'encapsulates': string
    'opened-connection': string
    'operating-system': string
    'parent': string
    'parent-directory': string
    'raw-email': string
    'src-payload': string
    'remediates': string
    'resolves-to': string
    'obs_resolves-to': string
    'revoked-by': string
    'sample': string
    'sender': string
    'src': string
    'to': string
    'values': string
    'static-analyses-of': string
    'subnarrative-of': string
    'subtechnique-of': string
    'numberOfConnectedElement': string
    'known-as': string
  }
}

interface ExtendedThemeOptions extends ThemeOptions {
  logo: string | null
  logo_collapsed: string | null
  palette: ExtendedPaletteOptions
  borderRadius: number
}

export interface Theme extends MuiTheme {
  logo: string | undefined
  logo_collapsed: string | undefined
  borderRadius: number
  palette: ExtendedPaletteOptions
}
