import { beforeEach, describe, expect, it, vi } from 'vitest';
import { MINIMAL_COMPATIBLE_SCOPE_VERSION, playbookImport } from '../../../../src/modules/playbook/playbook-domain';
import * as fileToContent from '../../../../src/utils/fileToContent';
import type { AuthContext } from '../../../../src/types/user';
import { ADMIN_USER } from '../../../utils/testQuery';
import type { FileHandle } from 'fs/promises';
import * as playbookUtils from '../../../../src/modules/playbook/playbook-utils';
import * as ee from '../../../../src/enterprise-edition/ee';
import * as middleware from '../../../../src/database/middleware';
import * as rabbitmq from '../../../../src/database/rabbitmq';
import * as redis from '../../../../src/database/redis';
import * as UserActionListener from '../../../../src/listener/UserActionListener';

describe('playbook-domain', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('playbookImport', () => {
    const parsedDataOldVersionMock = { openCTI_version: '6.9.0', type: 'playbook', configuration: {} };
    const parsedDataNewVersionMock = { openCTI_version: '8.260428.0', type: 'playbook', configuration: {} };
    const parsedDataSameVersionMock = { openCTI_version: MINIMAL_COMPATIBLE_SCOPE_VERSION, type: 'playbook', configuration: {} };
    const contextMock = { id: 'context' } as unknown as AuthContext;
    const fileMock = {} as unknown as Promise<FileHandle>;
    const dataMock = {} as Record<string, any>;
    const queueMock = {} as {
      connection: {
        host: any;
        vhost: any;
        use_ssl: boolean;
        port: any;
        user: any;
        pass: any;
      };
      s3: {
        endpoint: any;
        port: any;
        use_ssl: boolean;
        bucket_name: any;
        bucket_region: any;
        access_key: any;
        secret_key: any;
      };
      push: string;
      push_routing: string;
      push_exchange: string;
      listen: string;
      listen_routing: string;
      listen_exchange: string;
      listen_callback_uri: undefined;
      dead_letter_routing: string;
    };

    beforeEach(() => {
      vi.spyOn(playbookUtils, 'updateImportedPlaybookDefinitionScope').mockReturnValue('newPlaybookDefinition');
      vi.spyOn(ee, 'checkEnterpriseEdition').mockResolvedValue();
      vi.spyOn(middleware, 'createEntity').mockResolvedValue(dataMock);
      vi.spyOn(rabbitmq, 'registerConnectorQueues').mockResolvedValue(queueMock);
      vi.spyOn(redis, 'notify').mockResolvedValue({ id: 'test' });
      vi.spyOn(UserActionListener, 'publishUserAction').mockResolvedValue([]);
    });

    it('should not call updatePlaybookDefinitionWithNewScope when the playbook version is older than MINIMAL_COMPATIBLE_SCOPE_VERSION', async () => {
      vi.spyOn(fileToContent, 'extractContentFrom').mockResolvedValue(parsedDataOldVersionMock);

      const result = await playbookImport(contextMock, ADMIN_USER, fileMock);
      expect(result).toEqual('test');
      expect(playbookUtils.updateImportedPlaybookDefinitionScope).not.toHaveBeenCalled();
    });

    it('should call updatePlaybookDefinitionWithNewScope when the playbook version is newer than MINIMAL_COMPATIBLE_SCOPE_VERSION', async () => {
      vi.spyOn(fileToContent, 'extractContentFrom').mockResolvedValue(parsedDataNewVersionMock);

      const result = await playbookImport(contextMock, ADMIN_USER, fileMock);
      expect(result).toEqual('test');
      expect(playbookUtils.updateImportedPlaybookDefinitionScope).toHaveBeenCalled();
    });

    it('should call updatePlaybookDefinitionWithNewScope when the playbook version equals than MINIMAL_COMPATIBLE_SCOPE_VERSION', async () => {
      vi.spyOn(fileToContent, 'extractContentFrom').mockResolvedValue(parsedDataSameVersionMock);

      const result = await playbookImport(contextMock, ADMIN_USER, fileMock);
      expect(result).toEqual('test');
      expect(playbookUtils.updateImportedPlaybookDefinitionScope).toHaveBeenCalled();
    });
  });
});
