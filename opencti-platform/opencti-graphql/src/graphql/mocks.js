// Custom scalars
import { 
  DateTimeMock,
  EmailAddressMock,
  IPv4Mock,
  IPv6Mock,
  LatitudeMock,
  LongitudeMock,
  MACMock,
  PhoneNumberMock,
  PortMock,
  PositiveIntMock,
  PostalCodeMock,
  URLMock,
  VoidMock,
} from 'graphql-scalars';

const mocks = {
  DateTime: DateTimeMock,
  EmailAddress: EmailAddressMock,
  IPv4: IPv4Mock,
  IPv6: IPv6Mock,
  Latitude: LatitudeMock,
  Longitude: LongitudeMock,
  MAC: MACMock,
  PhoneNumber: PhoneNumberMock,
  Port: PortMock,
  PositiveInt: PositiveIntMock,
  PostalCode: PostalCodeMock,
  URL: URLMock,
  Void: VoidMock,
  AssetLocation: () => ({
    id: 'location--befc3ca8-79a6-4d59-b535-ed53bf2f7c51',
    entity_type: 'location',
    name: 'DarkLight Headquarters',
    street_address: '8201 164th Ave NE',
    city: 'Redmond',
    administrative_area: 'WA',
    postal_code: '98052',
    country: 'US'
  }),
  CyioExternalReference: () => ({
    source_name: 'Alienware',
    description: 'Aurora-R4 Owners manual',
    external_id: 'aurora-r4-owner',
    url: 'https://downloads.dell.com/manuals/all-products/esuprt_desktop/esuprt_alienware_dsk/alienware-aurora-r4_owner%27s%20manual_en-us.pdf'
  }),
  ComputingDevice: () => ({
    id: 'computing-device--204d01a8-4866-4144-b7ff-a6ba40127a2d',
    asset_id: 'darklight-2021-125',
    asset_type: 'compute_device',
    asset_tag: 'MM249847',
    name: 'Paul Patrick Personal Macbook Pro',
    description: 'Macbook Pro (16-inch 2019)',
    serial_number: 'C02D20NFMD6T',
    mac_address: ['14:b1:c8:01:9c:11'],
    vendor_name: 'Apple',
    implementation_point: 'external',
    operational_status: 'operational',
    function: 'Developer laptop',
    network_id: '192.168.1.255'
  }),
  OperatingSystem: () => ({
    id: 'software--29da67b2-b7eb-4c1a-9458-348669b77a0e',
    asset_type: 'operating_system',
    asset_id: 'darklight-2021-100',
    name: 'MacOS 11.6 (20G165)',
    description: 'MacOS',
    vendor_name: 'Apple',
    version: '11.6',
  }),
};

export default mocks ;
