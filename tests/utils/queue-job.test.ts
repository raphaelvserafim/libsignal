import { describe, it, expect } from 'vitest';
import queueJob from '../../src/utils/queue-job';

describe('queueJob', () => {
  it('should execute a simple job', async () => {
    const result = await queueJob('test-bucket-1', async () => 42);
    expect(result).toBe(42);
  });

  it('should serialize jobs on the same bucket', async () => {
    const order: number[] = [];
    const p1 = queueJob('serial-bucket', async () => {
      await new Promise(r => setTimeout(r, 50));
      order.push(1);
      return 1;
    });
    const p2 = queueJob('serial-bucket', async () => {
      order.push(2);
      return 2;
    });
    const [r1, r2] = await Promise.all([p1, p2]);
    expect(r1).toBe(1);
    expect(r2).toBe(2);
    expect(order).toEqual([1, 2]);
  });

  it('should allow parallel jobs on different buckets', async () => {
    const order: string[] = [];
    const p1 = queueJob('bucket-a', async () => {
      await new Promise(r => setTimeout(r, 30));
      order.push('a');
      return 'a';
    });
    const p2 = queueJob('bucket-b', async () => {
      order.push('b');
      return 'b';
    });
    await Promise.all([p1, p2]);
    // b should finish first since it has no delay
    expect(order[0]).toBe('b');
  });

  it('should propagate errors', async () => {
    await expect(queueJob('err-bucket', async () => {
      throw new Error('test error');
    })).rejects.toThrow('test error');
  });

  it('should continue processing after error', async () => {
    const p1 = queueJob('recover-bucket', async () => {
      throw new Error('fail');
    }).catch(() => 'caught');
    const p2 = queueJob('recover-bucket', async () => 'ok');
    const [r1, r2] = await Promise.all([p1, p2]);
    expect(r1).toBe('caught');
    expect(r2).toBe('ok');
  });
});
