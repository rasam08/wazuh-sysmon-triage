import type { CancelRunResult, RunExecutionResult, Runner } from './runner';
import type { RunParams } from './validators';

export interface RunExecutor {
  startRun: (params: RunParams) => Promise<RunExecutionResult>;
  cancelRun: (caseId: string) => CancelRunResult;
  getActiveCaseId: () => string | null;
}

export function createRunExecutor(runner: Runner): RunExecutor {
  return {
    startRun: (params) => runner.startRun(params),
    cancelRun: (caseId) => runner.cancelRun(caseId),
    getActiveCaseId: () => runner.getActiveCaseId(),
  };
}

