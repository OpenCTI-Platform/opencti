import { ENTITY_TYPE_CONTAINER_REPORT, generateStandardId } from '../../../src/utils/idGenerator';

test('should report ids stable', () => {
  const data = {
    id: 'report--a445d22a-db0c-4b5d-9ec8-e9ad0b6dbdd7',
    type: 'report',
    spec_version: '2.1',
    name: 'A demo report for testing purposes',
    labels: ['report'],
    description: 'Report for testing purposes (random data).',
    published: '2020-03-01T14:02:48.111Z',
    created: '2020-03-01T14:02:55.327Z',
    modified: '2020-03-01T14:09:48.078Z',
    report_types: ['threat-report'],
    x_opencti_report_status: 2,
    confidence: 3,
    x_opencti_graph_data:
      'eyJub2RlcyI6eyJhYjc4YTYyZi00OTI4LTRkNWEtODc0MC0wM2YwYWY5YzQzMzAiOnsicG9zaXRpb24iOnsieCI6MTIuNSwieSI6NDA1fX0sImU3NjUyY2I2LTc3N2EtNDIyMC05YjY0LTA1NDNlZjM2ZDQ2NyI6eyJwb3NpdGlvbiI6eyJ4IjoyNTIuNSwieSI6Mjk1fX0sImM4NzM5MTE2LWUxZDktNGM0Zi1iMDkxLTU5MDE0N2IzZDdiOSI6eyJwb3NpdGlvbiI6eyJ4IjoxMzIuNSwieSI6Mjk1fX0sIjFjNDc5NzBhLWEyM2ItNGI2Yy04NWNkLWFiNzNkZGI1MDZjNiI6eyJwb3NpdGlvbiI6eyJ4IjozNzcuNSwieSI6MH19LCI5Y2EyZmY0My1iNzY1LTRmMTMtYTIxMy0xMDY2NGEyYWU4ZmMiOnsicG9zaXRpb24iOnsieCI6NDg3LjUsInkiOjQwNX19LCJlMjc1MzMxMi0xMDkwLTQ5MmQtYThmZC01NmNhMzY2NzVkMzUiOnsicG9zaXRpb24iOnsieCI6NDg3LjUsInkiOjU5MH19LCJhZjU3MzljNy02ZGI5LTRmMmItYjg5NS04ZWVkNmJhM2Y1NmMiOnsicG9zaXRpb24iOnsieCI6NDg3LjUsInkiOjc3NX19LCI5ZjdmMDBmOS0zMDRiLTQwNTUtOGM0Zi1mNWVhZGIwMGRlM2IiOnsicG9zaXRpb24iOnsieCI6NSwieSI6NTkwfX0sImQxODgxMTY2LWY0MzEtNDMzNS1iZmVkLWIxYzY0N2U1OWY4OSI6eyJwb3NpdGlvbiI6eyJ4IjozNjcuNSwieSI6NDA1fX0sImYyZWE3ZDM3LTk5NmQtNDMxMy04ZjczLTQyYTg3ODJkMzlhMCI6eyJwb3NpdGlvbiI6eyJ4IjozNjcuNSwieSI6NTkwfX0sIjgyMzE2ZmZkLWEwZWMtNDUxOS1hNDU0LTY1NjZmOGY1Njc2YyI6eyJwb3NpdGlvbiI6eyJ4IjozNzcuNSwieSI6MTg1fX0sImRjYmFkY2QyLTkzNTktNDhhYy04Yjg2LTg4ZTM4YTA5MmEyYiI6eyJwb3NpdGlvbiI6eyJ4IjoxMzIuNSwieSI6NTkwfX0sIjIwOWNiZGYwLWZjNWUtNDdjOS04MDIzLWRkNzI0OTkzYWU1NSI6eyJwb3NpdGlvbiI6eyJ4IjowLCJ5Ijo1MTV9fSwiNTBhMjA1ZmEtOTJlYy00ZWM5LWJmNjItZTA2NWRkODVmNWQ0Ijp7InBvc2l0aW9uIjp7IngiOjEyNy41LCJ5Ijo1MTV9fSwiYzM1NzdlNDItMjliNy00OTg1LWJkYjktMGMwYjRjZTYxZTQzIjp7InBvc2l0aW9uIjp7IngiOjM3Mi41LCJ5IjoxMTB9fSwiODZiNThiZDUtNTA1ZS00MjhlLTg1NjQtZTQzNTJkNmIxYmM2Ijp7InBvc2l0aW9uIjp7IngiOjEyNy41LCJ5Ijo0MjIuNX19LCJlYzgyNDYxMy1hZGIxLTQ2OGUtYmRmMi05OGZiZTViMGFkNWUiOnsicG9zaXRpb24iOnsieCI6MjQ3LjUsInkiOjQyMi41fX0sImMwOTRkYmZlLTcwMzQtNDVmNi1hMjgzLWIwMGI2YTc0MGI2YyI6eyJwb3NpdGlvbiI6eyJ4IjozNjIuNSwieSI6MzEyLjV9fSwiOTdlYmM5YjMtOGEyNS00MjhhLTg1MjMtMWU4N2IyNzAxZDNkIjp7InBvc2l0aW9uIjp7IngiOjcuNSwieSI6MzEyLjV9fSwiMzZkNTkxYjYtNTRiOS00MTUyLWFiODktNzljN2RhZDcwOWY3Ijp7InBvc2l0aW9uIjp7IngiOjQ4Mi41LCJ5IjozMTIuNX19LCI3YmQ4N2VmOC0yMzgzLTQ2MjAtOGE0OC1lM2JlODc4ZmZmMzQiOnsicG9zaXRpb24iOnsieCI6MzYyLjUsInkiOjUxNX19LCIzOTIxODc0Mi02ZjgxLTQ5NWUtYWU0Ny1iODE0ZjhjMGRmNGUiOnsicG9zaXRpb24iOnsieCI6NDgyLjUsInkiOjcwMH19LCJiN2E0ZDg2Zi0yMjBlLTQxMmEtODEzNS02ZTlmYjlmN2IyOTYiOnsicG9zaXRpb24iOnsieCI6NDgyLjUsInkiOjUxNX19fSwiem9vbSI6NzguMTIwMjYyODUwMDE2ODMsIm9mZnNldFgiOjYwMC41NDgxMzg4MzQyMDEsIm9mZnNldFkiOjM2LjUxMTE0NDQxNzM4NDg1NX0=',
    created_by_ref: 'identity--7b82b010-b1c0-4dae-981f-7756374a17df',
    object_marking_refs: ['marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27'],
    object_refs: [
      'malware--faa5b705-cf44-4e50-8472-29e5fec43c3c',
      'indicator--10e9a46e-7edb-496b-a167-e27ea3ed0079',
      'indicator--51640662-9c78-4402-932f-1d4531624723',
      'indicator--a2f7504a-ea0d-48ed-a18d-cbf352fae6cf',
      'identity--c017f212-546b-4f21-999d-97d3dc558f7b',
      'identity--5a510e41-5cb2-45cc-a191-a4844ea0a141',
      'identity--062f72b1-7caf-4112-ab92-6211f7e7abc8',
      'attack-pattern--489a7797-01c3-4706-8cd1-ec56a9db3adc',
      'location--c3794ffd-0e71-4670-aa4d-978b4cbdc72c',
      'location--5acd8b26-51c2-4608-86ed-e9edd43ad971',
      'intrusion-set--18854f55-ac7c-4634-bd9a-352dd07613b7',
      'campaign--92d46985-17a6-4610-8be8-cc70c82ed214',
      'x-opencti-incident--0b626d41-1d8d-4b96-86fa-ad49cea2cfd4',
      'attack-pattern--2fc04aa5-48c1-49ec-919a-b88241ef1d17',
      'observed-data--7d258c31-9a26-4543-aecb-2abc5ed366be',
      'relationship--e35b3fc1-47f3-4ccb-a8fe-65a0864edd02',
      'relationship--1fc9b5f8-3822-44c5-85d9-ee3476ca26de',
      'relationship--b703f822-f6f0-4d96-9c9b-3fc0bb61e69c',
      'relationship--8d2200a8-f9ef-4345-95d1-ba3ed49606f9',
      'relationship--eedcea8f-a464-4977-955c-5113aa3c0896',
      'relationship--2326c8b3-ef45-4978-98d0-0059728275c4',
      'relationship--9f999fc5-5c74-4964-ab87-ee4c7cdc37a3',
      'relationship--3541149d-1af6-4688-993c-dc32c7ee3880',
      'relationship--3e10618c-a301-43db-87f3-91b9e397c30d',
      'relationship--d861deab-84b6-4dc9-bcce-594e3d1c904f',
      'relationship--307058e3-84f3-4e9c-8776-2e4fe4d6c6c7',
    ],
  };
  for (let i = 0; i < 100; i += 1) {
    const reportStandardId = generateStandardId(ENTITY_TYPE_CONTAINER_REPORT, data);
    expect(reportStandardId).toEqual('report--809c35ad-8015-5fc4-a7f7-ebffccf479c5');
  }
});
