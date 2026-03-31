import { describe, expect, it, vi, beforeEach } from 'vitest';
import { createDraftAndAskJobImport } from '../../../src/domain/connector';
import { addDraftWorkspace } from '../../../src/modules/draftWorkspace/draftWorkspace-domain';
import { loadFile, uploadJobImport } from '../../../src/database/file-storage';
import { internalLoadById } from '../../../src/database/middleware-loader';
import { publishUserAction, completeContextDataForEntity } from '../../../src/listener/UserActionListener';
import { addWorkbenchDraftConvertionCount, addWorkbenchValidationCount } from '../../../src/manager/telemetryManager';
import type { AuthContext, AuthUser } from '../../../src/types/user';
import { ValidationMode } from '../../../src/generated/graphql';

// ---------------------------------------------------------------------------
// Module mocks – only the functions called during createDraftAndAskJobImport
// and its internal call to askJobImport are mocked. Everything else in
// connector.ts is left real (consistent with the connector-stream-test.ts pattern).
// ---------------------------------------------------------------------------

vi.mock('../../../src/modules/draftWorkspace/draftWorkspace-domain', () => ({
  addDraftWorkspace: vi.fn(),
}));

vi.mock('../../../src/database/file-storage', () => ({
  loadFile: vi.fn(),
  uploadJobImport: vi.fn(),
  defaultValidationMode: 'workbench', // constant used as default for validationMode
}));

vi.mock('../../../src/database/middleware-loader', () => ({
  internalLoadById: vi.fn(),
  fullEntitiesList: vi.fn(),
  pageEntitiesConnection: vi.fn(),
  storeLoadById: vi.fn(),
}));

vi.mock('../../../src/listener/UserActionListener', () => ({
  publishUserAction: vi.fn(),
  completeContextDataForEntity: vi.fn(),
}));

vi.mock('../../../src/utils/confidence-level', () => ({
  controlUserConfidenceAgainstElement: vi.fn(),
}));

vi.mock('../../../src/database/entity-representative', () => ({
  extractEntityRepresentativeName: vi.fn().mockReturnValue(''),
}));

vi.mock('../../../src/manager/telemetryManager', () => ({
  addConnectorDeployedCount: vi.fn(),
  addWorkbenchDraftConvertionCount: vi.fn(),
  addWorkbenchValidationCount: vi.fn(),
}));

// ---------------------------------------------------------------------------
// Shared test fixtures
// ---------------------------------------------------------------------------

const testContext = {
  otp_mandatory: false,
  user_inside_platform_organization: false,
  source: 'test',
} as unknown as AuthContext;

const testUser = {
  id: 'test-user-id',
  user_email: 'test@opencti.io',
  name: 'Test User',
} as unknown as AuthUser;

/** File whose id does NOT start with 'import/pending' → no telemetry counters */
const mockRegularFile = {
  id: 'import/global/test-file.pdf',
  name: 'test-file.pdf',
  metaData: { entity_id: null, mimetype: 'application/pdf' },
};

/** File whose id starts with 'import/pending' → telemetry counter triggered */
const mockPendingFile = {
  id: 'import/pending/test-file.pdf',
  name: 'test-file.pdf',
  metaData: { entity_id: null, mimetype: 'application/pdf' },
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('createDraftAndAskJobImport', () => {
  beforeEach(() => {
    vi.clearAllMocks();

    // Default happy-path setup
    vi.mocked(addDraftWorkspace).mockResolvedValue({ id: 'draft-id-123' } as never);
    vi.mocked(loadFile).mockResolvedValue(mockRegularFile as never);
    vi.mocked(uploadJobImport).mockResolvedValue([]);
    vi.mocked(internalLoadById).mockResolvedValue(null as never);
    vi.mocked(completeContextDataForEntity).mockReturnValue({} as never);
    vi.mocked(publishUserAction).mockResolvedValue(undefined as never);
  });

  // -----------------------------------------------------------------------
  // addDraftWorkspace calls
  // -----------------------------------------------------------------------

  describe('addDraftWorkspace', () => {
    it('should be called with fileName as the draft name', async () => {
      await createDraftAndAskJobImport(testContext, testUser, { fileName: 'report.pdf' });

      expect(addDraftWorkspace).toHaveBeenCalledWith(
        testContext,
        testUser,
        expect.objectContaining({ name: 'report.pdf' }),
      );
    });

    it('should forward description when provided', async () => {
      await createDraftAndAskJobImport(testContext, testUser, {
        fileName: 'report.pdf',
        description: 'Test description',
      });

      expect(addDraftWorkspace).toHaveBeenCalledWith(
        testContext,
        testUser,
        expect.objectContaining({ description: 'Test description' }),
      );
    });

    it('should forward entity_id when provided', async () => {
      await createDraftAndAskJobImport(testContext, testUser, {
        fileName: 'report.pdf',
        entity_id: 'entity-456',
      });

      expect(addDraftWorkspace).toHaveBeenCalledWith(
        testContext,
        testUser,
        expect.objectContaining({ entity_id: 'entity-456' }),
      );
    });

    it('should forward objectAssignee and objectParticipant when provided', async () => {
      await createDraftAndAskJobImport(testContext, testUser, {
        fileName: 'report.pdf',
        objectAssignee: ['user-1', 'user-2'],
        objectParticipant: ['user-3'],
      });

      expect(addDraftWorkspace).toHaveBeenCalledWith(
        testContext,
        testUser,
        expect.objectContaining({
          objectAssignee: ['user-1', 'user-2'],
          objectParticipant: ['user-3'],
        }),
      );
    });

    it('should forward createdBy when provided', async () => {
      await createDraftAndAskJobImport(testContext, testUser, {
        fileName: 'report.pdf',
        createdBy: 'author-1',
      });

      expect(addDraftWorkspace).toHaveBeenCalledWith(
        testContext,
        testUser,
        expect.objectContaining({ createdBy: 'author-1' }),
      );
    });

    it('should forward authorized_members when provided', async () => {
      const authorizedMembers = [{ id: 'user-1', access_right: 'view' }];
      await createDraftAndAskJobImport(testContext, testUser, {
        fileName: 'report.pdf',
        authorized_members: authorizedMembers as never,
      });

      expect(addDraftWorkspace).toHaveBeenCalledWith(
        testContext,
        testUser,
        expect.objectContaining({ authorized_members: authorizedMembers }),
      );
    });
  });

  // -----------------------------------------------------------------------
  // askJobImport context forwarding (validated through uploadJobImport calls)
  // -----------------------------------------------------------------------

  describe('draft context forwarding to askJobImport', () => {
    it('should inject the new draft id as draft_context in the context', async () => {
      vi.mocked(addDraftWorkspace).mockResolvedValue({ id: 'draft-abc-123' } as never);

      await createDraftAndAskJobImport(testContext, testUser, { fileName: 'report.pdf' });

      expect(uploadJobImport).toHaveBeenCalledWith(
        expect.objectContaining({ draft_context: 'draft-abc-123' }),
        testUser,
        mockRegularFile,
        undefined,
        expect.any(Object),
      );
    });

    it('should always set bypassValidation to true regardless of the arg', async () => {
      await createDraftAndAskJobImport(testContext, testUser, {
        fileName: 'report.pdf',
        bypassValidation: false, // intentionally wrong – must be overridden
      });

      expect(uploadJobImport).toHaveBeenCalledWith(
        expect.any(Object),
        testUser,
        mockRegularFile,
        undefined,
        expect.objectContaining({ bypassValidation: true }),
      );
    });

    it('should always set forceValidation to false regardless of the arg', async () => {
      await createDraftAndAskJobImport(testContext, testUser, {
        fileName: 'report.pdf',
        forceValidation: true, // intentionally wrong – must be overridden
      });

      expect(uploadJobImport).toHaveBeenCalledWith(
        expect.any(Object),
        testUser,
        mockRegularFile,
        undefined,
        expect.objectContaining({ forceValidation: false }),
      );
    });

    it('should use defaultValidationMode when validationMode is not provided', async () => {
      await createDraftAndAskJobImport(testContext, testUser, { fileName: 'report.pdf' });

      expect(uploadJobImport).toHaveBeenCalledWith(
        expect.any(Object),
        testUser,
        mockRegularFile,
        undefined,
        expect.objectContaining({ validationMode: 'workbench' }),
      );
    });

    it('should use the provided validationMode when specified', async () => {
      await createDraftAndAskJobImport(testContext, testUser, {
        fileName: 'report.pdf',
        validationMode: ValidationMode.Draft,
      });

      expect(uploadJobImport).toHaveBeenCalledWith(
        expect.any(Object),
        testUser,
        mockRegularFile,
        undefined,
        expect.objectContaining({ validationMode: ValidationMode.Draft }),
      );
    });

    it('should forward connectorId and configuration to askJobImport', async () => {
      await createDraftAndAskJobImport(testContext, testUser, {
        fileName: 'report.pdf',
        connectorId: 'connector-1',
        configuration: '{"key":"value"}',
      });

      expect(uploadJobImport).toHaveBeenCalledWith(
        expect.any(Object),
        testUser,
        mockRegularFile,
        undefined,
        expect.objectContaining({
          connectorId: 'connector-1',
          configuration: '{"key":"value"}',
        }),
      );
    });

    it('should forward bypassEntityId to askJobImport', async () => {
      vi.mocked(internalLoadById).mockResolvedValue({ entity_type: 'Report' } as never);

      await createDraftAndAskJobImport(testContext, testUser, {
        fileName: 'report.pdf',
        bypassEntityId: 'bypass-entity-id',
      });

      // bypassEntityId is used as entityId inside askJobImport
      expect(uploadJobImport).toHaveBeenCalledWith(
        expect.any(Object),
        testUser,
        mockRegularFile,
        'bypass-entity-id',
        expect.any(Object),
      );
    });
  });

  // -----------------------------------------------------------------------
  // Return value
  // -----------------------------------------------------------------------

  describe('return value', () => {
    it('should return the file returned by askJobImport on success', async () => {
      const result = await createDraftAndAskJobImport(testContext, testUser, {
        fileName: 'report.pdf',
      });

      expect(result).toBe(mockRegularFile);
    });

    it('should return null when the file is not found', async () => {
      vi.mocked(loadFile).mockResolvedValue(null as never);

      const result = await createDraftAndAskJobImport(testContext, testUser, {
        fileName: 'report.pdf',
      });

      expect(result).toBeNull();
    });

    it('should still create the draft even when the file is not found', async () => {
      vi.mocked(loadFile).mockResolvedValue(null as never);

      await createDraftAndAskJobImport(testContext, testUser, { fileName: 'missing.pdf' });

      expect(addDraftWorkspace).toHaveBeenCalledOnce();
    });
  });

  // -----------------------------------------------------------------------
  // Telemetry counters (only triggered for 'import/pending' files)
  // -----------------------------------------------------------------------

  describe('telemetry counters', () => {
    it('should call addWorkbenchValidationCount for import/pending files (bypassValidation is always true)', async () => {
      vi.mocked(loadFile).mockResolvedValue(mockPendingFile as never);

      await createDraftAndAskJobImport(testContext, testUser, { fileName: 'test-file.pdf' });

      expect(addWorkbenchValidationCount).toHaveBeenCalledOnce();
      expect(addWorkbenchDraftConvertionCount).not.toHaveBeenCalled();
    });

    it('should not call any telemetry counter for non-pending files', async () => {
      vi.mocked(loadFile).mockResolvedValue(mockRegularFile as never);

      await createDraftAndAskJobImport(testContext, testUser, { fileName: 'report.pdf' });

      expect(addWorkbenchValidationCount).not.toHaveBeenCalled();
      expect(addWorkbenchDraftConvertionCount).not.toHaveBeenCalled();
    });
  });
});

