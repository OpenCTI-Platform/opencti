import { describe, it, expect } from 'vitest';
import { Connector_connector$data } from '@components/data/connectors/__generated__/Connector_connector.graphql';
import canDeleteConnector from './canDeleteConnector';

describe('canDeleteConnector', () => {
  it('should return false for built-in connectors', () => {
    const connector = {
      built_in: true,
      is_managed: false,
      active: false,
    } as Connector_connector$data;

    expect(canDeleteConnector(connector)).toBe(false);
  });

  it('should return false for active non-managed connectors', () => {
    const connector = {
      built_in: false,
      is_managed: false,
      active: true,
    } as Connector_connector$data;

    expect(canDeleteConnector(connector)).toBe(false);
  });

  it('should return true for inactive non-managed connectors', () => {
    const connector = {
      built_in: false,
      is_managed: false,
      active: false,
    } as Connector_connector$data;

    expect(canDeleteConnector(connector)).toBe(true);
  });

  it('should return true for managed connectors with stopping requested status', () => {
    const connector = {
      built_in: false,
      is_managed: true,
      manager_requested_status: 'stopping',
      manager_current_status: 'started',
    } as Connector_connector$data;

    expect(canDeleteConnector(connector)).toBe(true);
  });

  it('should return true for managed connectors with stopped requested status', () => {
    const connector = {
      built_in: false,
      is_managed: true,
      manager_requested_status: 'stopped',
      manager_current_status: 'started',
    } as Connector_connector$data;

    expect(canDeleteConnector(connector)).toBe(true);
  });

  it('should return true for managed connectors with stopped current status', () => {
    const connector = {
      built_in: false,
      is_managed: true,
      manager_requested_status: null,
      manager_current_status: 'stopped',
    } as Connector_connector$data;

    expect(canDeleteConnector(connector)).toBe(true);
  });

  it('should return false for managed connectors that are running without stop request', () => {
    const connector = {
      built_in: false,
      is_managed: true,
      manager_requested_status: 'started',
      manager_current_status: 'started',
    } as Connector_connector$data;

    expect(canDeleteConnector(connector)).toBe(false);
  });

  it('should return false for managed built-in connectors even if stopped', () => {
    const connector = {
      built_in: true,
      is_managed: true,
      manager_requested_status: 'stopped',
      manager_current_status: 'stopped',
    } as Connector_connector$data;

    expect(canDeleteConnector(connector)).toBe(false);
  });
});
