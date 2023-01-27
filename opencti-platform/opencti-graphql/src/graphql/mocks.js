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
    country: 'US',
  }),
  CyioExternalReference: () => ({
    source_name: 'Alienware',
    description: 'Aurora-R4 Owners manual',
    external_id: 'aurora-r4-owner',
    url: 'https://downloads.dell.com/manuals/all-products/esuprt_desktop/esuprt_alienware_dsk/alienware-aurora-r4_owner%27s%20manual_en-us.pdf',
  }),
};

export default mocks;
