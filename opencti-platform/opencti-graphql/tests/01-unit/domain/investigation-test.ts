import { describe, expect, it } from 'vitest';
import { nameInvestigationToStartFromContainer } from '../../../src/modules/workspace/investigation-domain';
import type { BasicStoreEntity } from '../../../src/types/store';

describe('nameInvestigationToStartFromContainer', () => {
  describe('without other started investigations', () => {
    it('names the investigation to start from a container with its name and type', () => {
      const aContainer = {
        entity_type: 'Report',
        name: 'a report'
      };

      const investigationName = nameInvestigationToStartFromContainer([], <BasicStoreEntity>aContainer);

      expect(investigationName).toEqual('investigation from report "a report"');
    });

    it('names the successive investigations to start from a container with its name, type and a number suffix', () => {
      const aContainer = {
        entity_type: 'Report',
        name: 'a report'
      };
      const investigationsNames: string[] = ['investigation from report "a report"'];

      const secondInvestigationName = nameInvestigationToStartFromContainer(investigationsNames, <BasicStoreEntity>aContainer);
      const thirdInvestigationName = nameInvestigationToStartFromContainer([...investigationsNames, secondInvestigationName], <BasicStoreEntity>aContainer);

      expect(secondInvestigationName).toEqual('investigation from report "a report" 2');
      expect(thirdInvestigationName).toEqual('investigation from report "a report" 3');
    });

    it('investigations to start from a container are numbered accordingly even when the container name has a number on its own', () => {
      const aContainer = {
        entity_type: 'Report',
        name: 'report number 1'
      };
      const investigationsNames: string[] = ['investigation from report "report number 1"'];

      const secondInvestigationName = nameInvestigationToStartFromContainer(investigationsNames, <BasicStoreEntity>aContainer);
      const thirdInvestigationName = nameInvestigationToStartFromContainer([...investigationsNames, secondInvestigationName], <BasicStoreEntity>aContainer);

      expect(secondInvestigationName).toEqual('investigation from report "report number 1" 2');
      expect(thirdInvestigationName).toEqual('investigation from report "report number 1" 3');
    });
  });

  describe('with other started investigations', () => {
    it('names the first investigation to start from another container with its name and type and a number', () => {
      const aGrouping = {
        entity_type: 'Grouping',
        name: 'a grouping'
      };
      const investigationsNames: string[] = ['investigation from report "a report"'];

      const investigationName = nameInvestigationToStartFromContainer(investigationsNames, <BasicStoreEntity>aGrouping);

      expect(investigationName).toEqual('investigation from grouping "a grouping"');
    });
  });

  describe('with other investigations', () => {
    it('names the first investigation to start from a container with its name and type and a number', () => {
      const aGrouping = {
        entity_type: 'Grouping',
        name: 'a grouping'
      };
      const investigationsNames: string[] = ['investigation de malware'];

      const investigationName = nameInvestigationToStartFromContainer(investigationsNames, <BasicStoreEntity>aGrouping);

      expect(investigationName).toEqual('investigation from grouping "a grouping"');
    });

    it('names the successive investigations to start from a container with its name, type and a number suffix', () => {
      const aReport = {
        entity_type: 'Report',
        name: 'a report'
      };
      const investigationsNames: string[] = ['investigation de malware', 'investigation from report "a report"'];

      const secondInvestigationName = nameInvestigationToStartFromContainer(investigationsNames, <BasicStoreEntity>aReport);
      const thirdInvestigationName = nameInvestigationToStartFromContainer([...investigationsNames, secondInvestigationName], <BasicStoreEntity>aReport);

      expect(secondInvestigationName).toEqual('investigation from report "a report" 2');
      expect(thirdInvestigationName).toEqual('investigation from report "a report" 3');
    });
  });
});
