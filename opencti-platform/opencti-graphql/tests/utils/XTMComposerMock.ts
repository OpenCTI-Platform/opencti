import gql from 'graphql-tag';
import { queryAsAdminWithSuccess } from './testQueryHelper';

/**
 * XTM Composer Mock - TypeScript implementation
 * Simulates the behavior of the XTM Composer container orchestrator
 */

// Types matching the Rust implementation
export enum ConnectorStatus {
  Started = 'started',
  Stopped = 'stopped',
}

export enum RequestedStatus {
  Starting = 'starting',
  Stopping = 'stopping',
}

export interface ApiConnector {
  id: string;
  name: string;
  image: string;
  contractHash: string;
  currentStatus?: string;
  requestedStatus: string;
  contractConfiguration: Array<{ key: string; value: string }>;
}

export interface OrchestratorContainer {
  id: string;
  name: string;
  state: string;
  labels: Record<string, string>;
  envs: Record<string, string>;
}

export interface XTMComposerMockConfig {
  logToConsole?: boolean;
  operationDelay?: number; // milliseconds
  failureRate?: number; // 0-1 probability of operation failure
  managerId?: string;
}

export class XTMComposerMock {
  private containers: Map<string, OrchestratorContainer> = new Map();

  private connectors: Map<string, ApiConnector> = new Map();

  private logToConsole: boolean;

  private operationDelay: number;

  private failureRate: number;

  private managerId: string;

  private adminClient: any;

  constructor(config: XTMComposerMockConfig = {}, adminClient?: any) {
    this.logToConsole = config.logToConsole || false;
    this.operationDelay = config.operationDelay || 1000;
    this.failureRate = config.failureRate || 0;
    this.managerId = config.managerId || 'xtm-composer-mock';
    this.adminClient = adminClient;
  }

  // Helper method for logging
  private log(level: 'info' | 'warn' | 'debug', message: string, context?: Record<string, any>): void {
    if (!this.logToConsole) return;

    const timestamp = new Date().toISOString();
    const contextStr = context ? ` ${JSON.stringify(context)}` : '';
    const formattedMessage = `[${timestamp}] ${level.toUpperCase()}: ${message}${contextStr}`;

    switch (level) {
      case 'info':
        console.log(formattedMessage); // eslint-disable-line no-console
        break;
      case 'warn':
        console.warn(formattedMessage); // eslint-disable-line no-console
        break;
      case 'debug':
        console.debug(formattedMessage); // eslint-disable-line no-console
        break;
      default:
        console.log(formattedMessage); // eslint-disable-line no-console
    }
  }

  // Helper methods
  private async simulateDelay(): Promise<void> {
    await new Promise<void>((resolve) => {
      setTimeout(resolve, this.operationDelay);
    });
  }

  private shouldFail(): boolean {
    return Math.random() < this.failureRate;
  }

  private static containerNameFromConnector(connector: ApiConnector): string {
    return connector.name
      .replace(/[^a-zA-Z0-9]/g, '-')
      .toLowerCase();
  }

  private createContainer(connector: ApiConnector): OrchestratorContainer {
    const containerName = XTMComposerMock.containerNameFromConnector(connector);
    const envs: Record<string, string> = {};

    // Add connector configuration as environment variables
    connector.contractConfiguration.forEach((config) => {
      envs[config.key] = config.value;
    });

    // Add OpenCTI specific environment variables
    envs.OPENCTI_URL = 'http://localhost:8080'; // Mock URL
    envs.OPENCTI_CONFIG_HASH = connector.contractHash;

    return {
      id: `container-${connector.id}`,
      name: containerName,
      state: 'created',
      labels: {
        'opencti-manager': this.managerId,
        'opencti-connector-id': connector.id,
      },
      envs,
    };
  }

  private static getConnectorStatus(state: string): ConnectorStatus {
    switch (state) {
      case 'running':
      case 'healthy':
      case 'started':
        return ConnectorStatus.Started;
      default:
        return ConnectorStatus.Stopped;
    }
  }

  // GraphQL methods
  static async updateConnectorLogs(connectorId: string, logs: string[]): Promise<string> {
    const mutation = gql`
      mutation UpdateConnectorLogs($input: LogsConnectorStatusInput!) {
        updateConnectorLogs(input: $input)
      }
    `;

    const result = await queryAsAdminWithSuccess({
      query: mutation,
      variables: { input: { id: connectorId, logs } }
    });

    return result.data?.updateConnectorLogs;
  }

  static async updateConnectorCurrentStatus(connectorId: string, status: string): Promise<any> {
    const mutation = gql`
      mutation UpdateConnectorCurrentStatus($input: CurrentConnectorStatusInput!) {
        updateConnectorCurrentStatus(input: $input) {
          id
          manager_current_status
        }
      }
    `;

    const result = await queryAsAdminWithSuccess({
      query: mutation,
      variables: { input: { id: connectorId, status } }
    });

    return result.data?.updateConnectorCurrentStatus;
  }

  static async getConnectorsForManagers(): Promise<any[]> {
    const query = gql`
      query ConnectorsForManagers {
        connectorsForManagers {
          id
          name
          manager_contract_image
          manager_requested_status
          manager_current_status
        }
      }
    `;

    const result = await queryAsAdminWithSuccess({
      query,
      variables: {}
    });

    return result.data?.connectorsForManagers;
  }

  // Workflow methods using GraphQL
  // eslint-disable-next-line class-methods-use-this
  async deployConnector(connectorId: string) {
    // 1. Get connector details
    const connectors = await XTMComposerMock.getConnectorsForManagers();
    const connector = connectors.find((c: any) => c.id === connectorId);

    if (!connector || connector.manager_requested_status !== 'starting') {
      throw new Error('Connector not found or not in starting state');
    }

    // 2. Simulate deployment logs
    await XTMComposerMock.updateConnectorLogs(connectorId, [
      '[XTM-Composer] Deploying connector...',
      `[XTM-Composer] Pulling image: ${connector.manager_contract_image}`,
      '[XTM-Composer] Creating container...',
      '[XTM-Composer] Starting container...'
    ]);

    // 3. Update status to started
    await XTMComposerMock.updateConnectorCurrentStatus(connectorId, 'started');

    // 4. Final log
    await XTMComposerMock.updateConnectorLogs(connectorId, [
      '[XTM-Composer] Connector deployed successfully'
    ]);
  }

  // eslint-disable-next-line class-methods-use-this
  async stopConnector(connectorId: string) {
    // 1. Update logs
    await XTMComposerMock.updateConnectorLogs(connectorId, [
      '[XTM-Composer] Stopping connector...',
      '[XTM-Composer] Sending termination signal...'
    ]);

    // 2. Update status
    await XTMComposerMock.updateConnectorCurrentStatus(connectorId, 'stopped');

    // 3. Final log
    await XTMComposerMock.updateConnectorLogs(connectorId, [
      '[XTM-Composer] Connector stopped successfully'
    ]);
  }

  async restartConnector(connectorId: string) {
    await this.stopConnector(connectorId);

    // Simulate restart delay
    await new Promise((resolve) => {
      setTimeout(resolve, 100);
    });

    await XTMComposerMock.updateConnectorLogs(connectorId, [
      '[XTM-Composer] Restarting connector...'
    ]);

    await XTMComposerMock.updateConnectorCurrentStatus(connectorId, 'started');

    await XTMComposerMock.updateConnectorLogs(connectorId, [
      '[XTM-Composer] Connector restarted successfully'
    ]);
  }

  // Wrapper methods for backward compatibility
  // eslint-disable-next-line class-methods-use-this
  async updateConnectorLogs(connectorId: string, logs: string[]): Promise<string> {
    return XTMComposerMock.updateConnectorLogs(connectorId, logs);
  }

  // eslint-disable-next-line class-methods-use-this
  async updateConnectorCurrentStatus(connectorId: string, status: string): Promise<any> {
    return XTMComposerMock.updateConnectorCurrentStatus(connectorId, status);
  }

  // eslint-disable-next-line class-methods-use-this
  async getConnectorsForManagers(): Promise<any[]> {
    return XTMComposerMock.getConnectorsForManagers();
  }

  // Main orchestrator methods
  async deploy(connector: ApiConnector): Promise<OrchestratorContainer | null> {
    const { id } = connector;
    this.log('info', 'Deploying the container', { id });

    await this.simulateDelay();

    if (this.shouldFail()) {
      this.log('warn', 'Deployment canceled', { id });
      return null;
    }

    // Simulate pulling the image
    this.log('info', `${connector.image} status "Pulling" progress "Pulling from library/${connector.image}" pulling...`);
    await this.simulateDelay();

    // Create the container
    const container = this.createContainer(connector);
    this.containers.set(container.name, container);

    // Store connector with updated status
    const updatedConnector = { ...connector, currentStatus: 'stopped' };
    this.connectors.set(connector.id, updatedConnector);

    // Start if requested
    if (connector.requestedStatus === 'starting') {
      await this.start(updatedConnector);
    }

    this.log('info', 'Container deployed successfully', { id, name: container.name });
    return container;
  }

  async start(connector: ApiConnector): Promise<void> {
    const { id } = connector;
    const containerName = XTMComposerMock.containerNameFromConnector(connector);
    const container = this.containers.get(containerName);

    if (!container) {
      throw new Error(`Container not found: ${containerName} (id: ${id})`);
    }

    this.log('info', 'Starting', { id });

    await this.simulateDelay();

    if (this.shouldFail()) {
      throw new Error(`Error starting container ${id}: Simulated failure`);
    }

    // Update container state
    container.state = 'running';

    // Update connector status in our internal map
    const storedConnector = this.connectors.get(id);
    if (storedConnector) {
      this.connectors.set(id, { ...storedConnector, currentStatus: 'started' });
    }

    this.log('info', 'Container started successfully', { id });
  }

  async stop(connector: ApiConnector): Promise<void> {
    const { id } = connector;
    const containerName = XTMComposerMock.containerNameFromConnector(connector);
    const container = this.containers.get(containerName);

    if (!container) {
      throw new Error(`Container not found: ${containerName} (id: ${id})`);
    }

    this.log('info', 'Stopping', { id });

    await this.simulateDelay();

    if (this.shouldFail()) {
      throw new Error(`Error stopping container ${id}: Simulated failure`);
    }

    // Update container state
    container.state = 'exited';

    // Update connector status in our internal map
    const storedConnector = this.connectors.get(id);
    if (storedConnector) {
      this.connectors.set(id, { ...storedConnector, currentStatus: 'stopped' });
    }

    this.log('info', 'Container stopped successfully', { id });
  }

  async restart(connector: ApiConnector): Promise<void> {
    const { id } = connector;
    this.log('info', 'Restarting connector', { id });

    // Stop first
    await this.stop(connector);

    // Then start
    await this.start(connector);

    this.log('info', 'Container restarted successfully', { id });
  }

  async delete(connector: ApiConnector): Promise<void> {
    const { id } = connector;
    const containerName = XTMComposerMock.containerNameFromConnector(connector);
    const container = this.containers.get(containerName);

    if (!container) {
      this.log('debug', 'Could not find docker container', { name: containerName });
      return;
    }

    this.log('info', 'Removing container', { name: containerName });

    await this.simulateDelay();

    if (this.shouldFail()) {
      throw new Error(`Could not remove container ${containerName}: Simulated failure`);
    }

    // Remove from internal state
    this.containers.delete(containerName);
    this.connectors.delete(id);

    this.log('info', 'Removed container', { name: containerName });
  }

  // Additional mock utilities
  async list(): Promise<OrchestratorContainer[]> {
    return Array.from(this.containers.values());
  }

  async get(connector: ApiConnector): Promise<OrchestratorContainer | null> {
    const containerName = XTMComposerMock.containerNameFromConnector(connector);
    const container = this.containers.get(containerName);

    if (!container) {
      this.log('debug', 'Could not find docker container', { name: containerName });
      return null;
    }

    return container;
  }

  async logs(connector: ApiConnector, tail: number = 100): Promise<string[]> {
    const containerName = XTMComposerMock.containerNameFromConnector(connector);
    const container = this.containers.get(containerName);

    if (!container) {
      return [];
    }

    // Simulate some log entries
    const mockLogs: string[] = [];
    const logCount = Math.min(tail, 20); // Generate up to 20 mock log entries

    for (let i = 0; i < logCount; i += 1) {
      const timestamp = new Date(Date.now() - (logCount - i) * 60000).toISOString();
      mockLogs.push(`[${timestamp}] Connector ${connector.name} processing...`);
    }

    // Update connector logs via GraphQL
    await XTMComposerMock.updateConnectorLogs(connector.id, mockLogs);

    this.log('info', 'Reporting logs', { id: connector.id });
    return mockLogs;
  }

  // Orchestration simulation
  async orchestrate(connectors: ApiConnector[]): Promise<void> {
    this.log('info', 'Starting orchestration cycle');

    // Process each connector
    await Promise.all(connectors.map(async (connector) => {
      const container = await this.get(connector);

      if (!container) {
        // Container doesn't exist, deploy it
        await this.deploy(connector);
      } else {
        // Container exists, check if action needed
        const currentStatus = XTMComposerMock.getConnectorStatus(container.state);
        const requestedStatus = connector.requestedStatus as RequestedStatus;

        // Handle status transitions
        if (requestedStatus === RequestedStatus.Stopping && currentStatus === ConnectorStatus.Started) {
          await this.stop(connector);
        } else if (requestedStatus === RequestedStatus.Starting && currentStatus === ConnectorStatus.Stopped) {
          await this.start(connector);
        } else {
          this.log('info', 'Nothing to execute', { id: connector.id });
        }

        // Check if refresh needed (version mismatch)
        if (container.envs.OPENCTI_CONFIG_HASH !== connector.contractHash) {
          this.log('info', 'Refreshing', {
            id: connector.id,
            hash: connector.contractHash
          });
          await this.delete(connector);
          await this.deploy(connector);
        }
      }
    }));

    // Clean up containers not in connector list
    const connectorIds = new Set(connectors.map((c) => c.id));
    const containersToRemove: string[] = [];

    this.containers.forEach((container, name) => {
      const connectorId = container.labels['opencti-connector-id'];
      if (!connectorIds.has(connectorId)) {
        containersToRemove.push(name);
      }
    });

    await Promise.all(containersToRemove.map(async (name) => {
      await this.simulateDelay();
      this.containers.delete(name);
      this.log('info', 'Removed orphaned container', { name });
    }));

    this.log('info', 'Orchestration cycle completed');
  }

  // Test helpers
  getContainerCount(): number {
    return this.containers.size;
  }

  getConnectorCount(): number {
    return this.connectors.size;
  }

  reset(): void {
    this.containers.clear();
    this.connectors.clear();
    this.log('info', 'Mock state reset');
  }
}

// Example usage
export function createExampleConnector(id: string, name: string, requestedStatus: string = 'starting'): ApiConnector {
  return {
    id,
    name,
    image: 'opencti/connector-sample:latest',
    contractHash: 'abc123def456',
    requestedStatus,
    contractConfiguration: [
      { key: 'CONNECTOR_ID', value: id },
      { key: 'CONNECTOR_NAME', value: name },
      { key: 'CONNECTOR_SCOPE', value: 'global' },
    ],
  };
}
