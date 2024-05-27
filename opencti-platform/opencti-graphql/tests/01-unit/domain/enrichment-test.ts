import { describe, expect, it } from 'vitest';
import { filterConnectorsForElementEnrichment } from '../../../src/domain/enrichment';
import { testContext } from '../../utils/testQuery';
import { ENTITY_TYPE_EXTERNAL_REFERENCE } from '../../../src/schema/stixMetaObject';

import internalConnectors from '../../data/connectors/internal-connectors.json';

describe('Enrichment domain filter connector unit testing', () => {
  const externalReferenceElement = {
    _index: 'opencti_stix_meta_objects',
    source_name: 'AlienVault',
    url: 'https://cert.gov.ua/article/6279600',
    confidence: 100,
    entity_type: 'External-Reference',
    internal_id: '822363f9-5edc-4b52-bfb9-9bea3df12f4c',
    standard_id: 'external-reference--46263753-2d5e-59f7-ae0d-09cd69f84f98',
    creator_id: [
      'cae57c08-a936-4e45-9de5-4e4a00b01a3f'
    ],
    created_at: '2024-06-07T09:43:34.910Z',
    updated_at: '2024-06-07T09:43:34.910Z',
    created: '2024-06-07T09:43:34.910Z',
    modified: '2024-06-07T09:43:34.910Z',
    id: '822363f9-5edc-4b52-bfb9-9bea3df12f4c',
    base_type: 'ENTITY',
    parent_types: [
      'Basic-Object',
      'Stix-Object',
      'Stix-Meta-Object'
    ]
  };
  const connectors = [...internalConnectors];
  const externalRefScope = ENTITY_TYPE_EXTERNAL_REFERENCE;
  it('should find enrichment connector with filter', async () => {
    const targetConnectors = await filterConnectorsForElementEnrichment(testContext, connectors, externalReferenceElement, externalRefScope);
    expect(targetConnectors.length).toEqual(1);
    expect(targetConnectors[0].name).toEqual('ImportExternalReference');
    expect(targetConnectors[0].connector_type).toEqual('INTERNAL_ENRICHMENT');
    expect(targetConnectors[0].connector_scope).toEqual(['External-Reference']);
  });
  it('should find enrichment connector if auto true and no filters', async () => {
    let testConnectors = [...connectors];
    let importExternalRefConnector = testConnectors.find((c) => c.name === 'ImportExternalReference');
    if (importExternalRefConnector) {
      importExternalRefConnector = { ...importExternalRefConnector };
      importExternalRefConnector.auto = true;
      importExternalRefConnector.connector_trigger_filters = '';
      testConnectors = testConnectors.filter((c) => c.name !== 'ImportExternalReference');
      testConnectors.push(importExternalRefConnector);
    }
    const targetConnectors = await filterConnectorsForElementEnrichment(testContext, testConnectors, externalReferenceElement, externalRefScope);
    expect(targetConnectors.length).toEqual(1);
    expect(targetConnectors[0].name).toEqual('ImportExternalReference');
    expect(targetConnectors[0].auto).toEqual(true);
  });
  it('should not find enrichment connector with creator filter', async () => {
    // change element creator to not match the filters
    const notMatchingElement = { ...externalReferenceElement, creator_id: ['88ec0c6a-13ce-5e39-b486-354fe4a7084f'] };
    const targetConnectors = await filterConnectorsForElementEnrichment(testContext, connectors, notMatchingElement, externalRefScope);
    expect(targetConnectors.length).toEqual(0);
  });
  it('should not find enrichment connector with creator filter & auto true', async () => {
    // replace auto true in import external reference connector
    let testConnectors = [...connectors];
    let importExternalRefConnector = testConnectors.find((c) => c.name === 'ImportExternalReference');
    if (importExternalRefConnector) {
      importExternalRefConnector = { ...importExternalRefConnector };
      importExternalRefConnector.auto = true;
      testConnectors = testConnectors.filter((c) => c.name !== 'ImportExternalReference');
      testConnectors.push(importExternalRefConnector);
    }
    // change element creator to not match the filters
    const notMatchingElement = { ...externalReferenceElement, creator_id: ['88ec0c6a-13ce-5e39-b486-354fe4a7084f'] };
    const targetConnectors = await filterConnectorsForElementEnrichment(testContext, testConnectors, notMatchingElement, externalRefScope);
    expect(targetConnectors.length).toEqual(0);
  });
  it('should not find enrichment connector if not auto and no filters', async () => {
    let testConnectors = [...connectors];
    let importExternalRefConnector = testConnectors.find((c) => c.name === 'ImportExternalReference');
    if (importExternalRefConnector) {
      importExternalRefConnector = { ...importExternalRefConnector };
      importExternalRefConnector.auto = false;
      importExternalRefConnector.connector_trigger_filters = '';
      testConnectors = testConnectors.filter((c) => c.name !== 'ImportExternalReference');
      testConnectors.push(importExternalRefConnector);
    }
    const targetConnectors = await filterConnectorsForElementEnrichment(testContext, testConnectors, externalReferenceElement, externalRefScope);
    expect(targetConnectors.length).toEqual(0);
  });
  it('should find no connectors when empty', async () => {
    const targetConnectors = await filterConnectorsForElementEnrichment(testContext, [], externalReferenceElement, externalRefScope);
    expect(targetConnectors.length).toEqual(0);
  });
});
