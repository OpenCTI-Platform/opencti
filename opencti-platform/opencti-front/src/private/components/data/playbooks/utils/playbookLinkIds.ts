import type { PlaybookDefinitionEdge } from '../types/playbook-types';

// The canvas must show every link under the id the server stored, or a later playbookRelink /
// playbookDeleteLink on it answers "Playbook link not found".

// playbookAddNode answers the new step's id only; the link from its parent gets an id of the
// server's own. It is read back from the stored definition: the one link from that parent port
// to the new step (the server refuses duplicates, so there is at most one).
export const linkIdFromDefinition = (
  definition: string | null | undefined,
  parentNodeId: string,
  parentPortId: string,
  nodeId: string,
): string | undefined => {
  if (!definition) return undefined;
  let links: PlaybookDefinitionEdge[];
  try {
    links = (JSON.parse(definition) as { links?: PlaybookDefinitionEdge[] }).links ?? [];
  } catch {
    return undefined;
  }
  return links.find((l) => l.from.id === parentNodeId && l.from.port === parentPortId && l.to.id === nodeId)?.id;
};

// playbookInsertNode on the link `insertedOnLinkId` (parent -> child): the server creates a NEW link
// parent -> new step under the returned linkId, and keeps the former link's id on new step -> child.
export const insertedLinkIds = (insertedOnLinkId: string, result: { linkId?: string }) => ({
  toNewStep: result.linkId,
  fromNewStep: insertedOnLinkId,
});
