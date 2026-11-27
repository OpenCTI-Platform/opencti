// How far the preview of a bundle has got, for the dialog that waits for it. The preview is one request: the dialog asks, every second,
// how much of it is done. Kept in the memory of the node that computes it, only while it computes: another node, or no preview, has none.
interface ConfigPresetImportPreviewRun {
  percent: number;
  // The previews of the same file that run at once (the dialog asks twice when it opens in development): the last to end clears the run
  count: number;
}

const runs = new Map<string, ConfigPresetImportPreviewRun>();

const runKey = (userId: string, fileId: string) => `${userId}/${fileId}`;

export interface ConfigPresetImportPreviewProgress {
  // A percentage that only goes up: a preview that restarts does not send the bar back
  set: (percent: number) => void;
  end: () => void;
}

export const trackConfigPresetImportPreview = (userId: string, fileId: string): ConfigPresetImportPreviewProgress => {
  const key = runKey(userId, fileId);
  const run = runs.get(key) ?? { percent: 0, count: 0 };
  run.count += 1;
  runs.set(key, run);
  let ended = false;
  return {
    set: (percent) => {
      // 100 is when the preview is answered: the run is gone by then
      run.percent = Math.max(run.percent, Math.min(99, Math.round(percent)));
    },
    end: () => {
      if (ended) {
        return;
      }
      ended = true;
      run.count -= 1;
      if (run.count <= 0 && runs.get(key) === run) {
        runs.delete(key);
      }
    },
  };
};

// The percentage of the preview that runs for the file of the user, null when none does
export const getConfigPresetImportPreviewProgress = (userId: string, fileId: string): number | null => {
  return runs.get(runKey(userId, fileId))?.percent ?? null;
};
