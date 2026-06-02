/*
 * jobQueue manages multiple queues indexed by device to serialize
 * session I/O ops on the database.
 */

interface Job<T = unknown> {
  awaitable: () => Promise<T>;
  resolve: (value: T) => void;
  reject: (reason?: unknown) => void;
}

const _queueAsyncBuckets = new Map<string, Job[]>();
const _gcLimit = 10000;

async function _asyncQueueExecutor(queue: Job[], cleanup: () => void): Promise<void> {
  let offt = 0;
  while (true) {
    const limit = Math.min(queue.length, offt + _gcLimit);
    for (let i = offt; i < limit; i++) {
      const job = queue[i];
      try {
        job.resolve(await job.awaitable());
      } catch (e) {
        job.reject(e);
      }
    }
    if (limit < queue.length) {
      /* Perform lazy GC of queue for faster iteration. */
      if (limit >= _gcLimit) {
        queue.splice(0, limit);
        offt = 0;
      } else {
        offt = limit;
      }
    } else {
      break;
    }
  }
  cleanup();
}

/**
 * Executes an async awaitable on a serialized queue.
 *
 * @param bucket A key for the queue bucket.
 * @param awaitable The async awaitable function to execute.
 * @returns A Promise that resolves or rejects with the awaitable's result.
 */
export default function queueJob<T>(bucket: string, awaitable: () => Promise<T>): Promise<T> {
  if (!awaitable.name) {
    // Make debugging easier by adding a name to this function.
    Object.defineProperty(awaitable, 'name', { writable: true });
    (awaitable as { name: string }).name = bucket;
  }

  let inactive = false;
  if (!_queueAsyncBuckets.has(bucket)) {
    _queueAsyncBuckets.set(bucket, []);
    inactive = true;
  }

  const queue = _queueAsyncBuckets.get(bucket)!;

  const jobPromise = new Promise<T>((resolve, reject) => {
    queue.push({ awaitable, resolve, reject } as Job);
  });

  if (inactive) {
    /* An executor is not currently active; Start one now. */
    _asyncQueueExecutor(queue, () => _queueAsyncBuckets.delete(bucket));
  }

  return jobPromise;
}
