import { describe, expect, it } from 'vitest';
import type { StoreEntity } from '../../../src/types/store';
import { convertIdentityClass } from '../../../src/modules/form/form-utils';
import { completeEntity } from '../../../src/modules/form/form-domain';

describe('Form Intake - Identity Class Conversion', () => {
  describe('convertIdentityClass function', () => {
    it('should set identity_class to "individual" for Individual entity type', () => {
      const entity = { entity_type: 'Individual', name: 'John Doe' } as StoreEntity;
      convertIdentityClass('Individual', entity);
      expect(entity.identity_class).toBe('individual');
    });

    it('should set identity_class to "class" for Sector entity type', () => {
      const entity = { entity_type: 'Sector', name: 'Finance' } as StoreEntity;
      convertIdentityClass('Sector', entity);
      expect(entity.identity_class).toBe('class');
    });

    it('should set identity_class to "system" for System entity type', () => {
      const entity = { entity_type: 'System', name: 'Main Server' } as StoreEntity;
      convertIdentityClass('System', entity);
      expect(entity.identity_class).toBe('system');
    });
  });

  describe('completeEntity with Identity types', () => {
    it('should complete Individual entity with correct identity_class', () => {
      const entity = { entity_type: 'Individual', name: 'Jane Doe' } as StoreEntity;
      const completed = completeEntity('Individual', entity);

      expect(completed.identity_class).toBe('individual');
      expect(completed.internal_id).toBeDefined();
      expect(completed.id).toBe(completed.internal_id);
      expect(completed.created).toBeDefined();
      expect(completed.modified).toBeDefined();
    });

    it('should not override existing identity_class', () => {
      const entity = {
        entity_type: 'Individual',
        name: 'Test User',
        identity_class: 'individual',
      } as StoreEntity;
      const completed = completeEntity('Individual', entity);

      expect(completed.identity_class).toBe('individual');
    });

    it('should complete non-Identity entity without identity_class', () => {
      const entity = { entity_type: 'Malware', name: 'Ransomware', is_family: true } as StoreEntity;
      const completed = completeEntity('Malware', entity);

      expect(completed.identity_class).toBeUndefined();
      expect(completed.internal_id).toBeDefined();
    });
  });

  describe('Form Intake - Main Entity scenarios', () => {
    describe('Single main entity mode', () => {
      it('should create Individual with identity_class when mainEntityType is Individual', () => {
        const mainEntityType = 'Individual';
        let mainEntity = {
          entity_type: mainEntityType,
          name: 'John Smith',
          x_opencti_firstname: 'John',
          x_opencti_lastname: 'Smith',
        } as StoreEntity;

        mainEntity = completeEntity(mainEntityType, mainEntity);

        expect(mainEntity.entity_type).toBe('Individual');
        expect(mainEntity.identity_class).toBe('individual');
        expect(mainEntity.name).toBe('John Smith');
      });
    });

    describe('Multiple main entity mode (parsed)', () => {
      it('should create multiple Individuals with identity_class from parsed values', () => {
        const mainEntityType = 'Individual';
        const parsedValues = ['Alice Johnson', 'Bob Williams', 'Charlie Brown'];
        const mainEntities: StoreEntity[] = [];

        for (const name of parsedValues) {
          let mainEntity = {
            entity_type: mainEntityType,
            name,
          } as StoreEntity;
          mainEntity = completeEntity(mainEntityType, mainEntity);
          mainEntities.push(mainEntity);
        }

        expect(mainEntities).toHaveLength(3);
        mainEntities.forEach((entity, index) => {
          expect(entity.identity_class).toBe('individual');
          expect(entity.name).toBe(parsedValues[index]);
          expect(entity.internal_id).toBeDefined();
        });
      });
    });

    describe('Multiple main entity mode (multiple fields)', () => {
      it('should create multiple Individuals with identity_class from field groups', () => {
        const mainEntityType = 'Individual';
        const fieldGroups = [
          { name: 'Company A', description: 'First company' },
          { name: 'Company B', description: 'Second company' },
        ];
        const mainEntities: StoreEntity[] = [];

        for (const group of fieldGroups) {
          let mainEntity = {
            entity_type: mainEntityType,
            ...group,
          } as StoreEntity;
          mainEntity = completeEntity(mainEntityType, mainEntity);
          mainEntities.push(mainEntity);
        }

        expect(mainEntities).toHaveLength(2);
        mainEntities.forEach((entity) => {
          expect(entity.identity_class).toBe('individual');
        });
      });
    });
  });

  describe('Form Intake - Additional Entity scenarios', () => {
    describe('Single additional entity mode', () => {
      it('should create additional Individual with identity_class', () => {
        const additionalEntityType = 'Individual';
        let additionalEntity = {
          entity_type: additionalEntityType,
          name: 'Contact Person',
          contact_information: 'contact@example.com',
        } as StoreEntity;

        additionalEntity = completeEntity(additionalEntityType, additionalEntity);

        expect(additionalEntity.identity_class).toBe('individual');
      });

      it('should create additional Sector with identity_class', () => {
        const additionalEntityType = 'Sector';
        let additionalEntity = {
          entity_type: additionalEntityType,
          name: 'Partner Economic',
        } as StoreEntity;

        additionalEntity = completeEntity(additionalEntityType, additionalEntity);

        expect(additionalEntity.identity_class).toBe('class');
      });
    });

    describe('Multiple additional entities mode (parsed)', () => {
      it('should create multiple additional Individuals from parsed values', () => {
        const additionalEntityType = 'Individual';
        const parsedValues = ['Analyst 1', 'Analyst 2'];
        const additionalEntities: StoreEntity[] = [];

        for (const name of parsedValues) {
          let entity = {
            entity_type: additionalEntityType,
            name,
          } as StoreEntity;
          entity = completeEntity(additionalEntityType, entity);
          additionalEntities.push(entity);
        }

        additionalEntities.forEach((entity) => {
          expect(entity.identity_class).toBe('individual');
        });
      });

      it('should create multiple additional Systems from parsed values', () => {
        const additionalEntityType = 'System';
        const parsedValues = ['Server-01', 'Server-02', 'Workstation-01'];
        const additionalEntities: StoreEntity[] = [];

        for (const name of parsedValues) {
          let entity = {
            entity_type: additionalEntityType,
            name,
          } as StoreEntity;
          entity = completeEntity(additionalEntityType, entity);
          additionalEntities.push(entity);
        }

        expect(additionalEntities).toHaveLength(3);
        additionalEntities.forEach((entity) => {
          expect(entity.identity_class).toBe('system');
        });
      });
    });

    describe('Multiple additional entities mode (multiple fields)', () => {
      it('should create multiple additional Individuals from field groups', () => {
        const additionalEntityType = 'Individual';
        const fieldGroups = [
          { name: 'Vendor A' },
          { name: 'Partner B' },
        ];
        const additionalEntities: StoreEntity[] = [];

        for (const group of fieldGroups) {
          let entity = {
            entity_type: additionalEntityType,
            ...group,
          } as StoreEntity;
          entity = completeEntity(additionalEntityType, entity);
          additionalEntities.push(entity);
        }

        additionalEntities.forEach((entity) => {
          expect(entity.identity_class).toBe('individual');
        });
      });
    });
  });

  describe('Form Intake - Mixed entity types', () => {
    it('should handle main entity as Individual with additional entity Sector', () => {
      // Main entity - Individual
      const mainEntityType = 'Individual';
      let mainEntity = {
        entity_type: mainEntityType,
        name: 'Threat Actor Person',
      } as StoreEntity;
      mainEntity = completeEntity(mainEntityType, mainEntity);

      // Additional entity - Sector
      const additionalEntityType = 'Sector';
      let additionalEntity = {
        entity_type: additionalEntityType,
        name: 'Finance',
      } as StoreEntity;
      additionalEntity = completeEntity(additionalEntityType, additionalEntity);

      expect(mainEntity.identity_class).toBe('individual');
      expect(additionalEntity.identity_class).toBe('class');
    });

    it('should handle non-Identity main entity with multiple Identity additional entities', () => {
      const mainEntityType = 'Report';
      let mainEntity = {
        entity_type: mainEntityType,
        name: 'Threat Report 2024',
        published: new Date(),
      } as StoreEntity;
      mainEntity = completeEntity(mainEntityType, mainEntity);

      const additionalEntities: StoreEntity[] = [];

      // Individual
      let individual = { entity_type: 'Individual', name: 'Report Author' } as StoreEntity;
      individual = completeEntity('Individual', individual);
      additionalEntities.push(individual);

      // Sector
      let sector = { entity_type: 'Sector', name: 'Finance' } as StoreEntity;
      sector = completeEntity('Sector', sector);
      additionalEntities.push(sector);

      // Assertions
      expect(mainEntity.identity_class).toBeUndefined();
      expect(additionalEntities[0].identity_class).toBe('individual');
      expect(additionalEntities[1].identity_class).toBe('class');
    });
  });
});
