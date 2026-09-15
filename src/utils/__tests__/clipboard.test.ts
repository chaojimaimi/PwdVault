import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { copyWithTimeout } from '../clipboard';

// jsdom does not implement WebCrypto, and Node's real WebCrypto resolves
// off-thread (not in a deterministic number of microtasks), which makes
// fake-timer tests flaky under parallel load. Use a hermetic stand-in whose
// digest() resolves on the microtask queue; byte-equality semantics match
// SHA-256 for the "same text" comparisons these tests make.
vi.stubGlobal('crypto', {
  subtle: {
    digest: async (_algorithm: string, data: BufferSource): Promise<ArrayBuffer> =>
      new Uint8Array(data).slice().buffer as ArrayBuffer,
  },
});

const clipboardMock = {
  writeText: vi.fn<(text: string) => Promise<void>>().mockResolvedValue(undefined),
  readText: vi.fn<() => Promise<string>>().mockResolvedValue('secret'),
};

function stubClipboard(): void {
  Object.defineProperty(navigator, 'clipboard', {
    value: clipboardMock,
    configurable: true,
  });
}

async function copy(text: string): Promise<void> {
  // Flush the microtasks inside copyWithTimeout so the clear timer is
  // registered before the test advances the clock.
  await copyWithTimeout(text);
}

// The clear timer callback is async (read → digest → write); fake-timer
// advancement does not flush its whole promise chain, so flush explicitly.
async function flushMicrotasks(): Promise<void> {
  for (let i = 0; i < 10; i += 1) await Promise.resolve();
}

describe('copyWithTimeout', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    stubClipboard();
    clipboardMock.writeText.mockClear();
    clipboardMock.readText.mockClear();
    clipboardMock.readText.mockResolvedValue('secret');
  });

  afterEach(() => {
    vi.useRealTimers();
    // A3: drop any timer left over from a test so it cannot fire later and
    // clobber the next test's clipboard mock.
    Reflect.deleteProperty(navigator, 'clipboard');
  });

  it('clears the clipboard after the timeout', async () => {
    await copy('secret');

    await vi.advanceTimersByTimeAsync(30_000);
    await flushMicrotasks();

    expect(clipboardMock.readText).toHaveBeenCalledTimes(1);
    expect(clipboardMock.writeText).toHaveBeenLastCalledWith('');
  });

  it('does not clear the clipboard when the user changed it', async () => {
    clipboardMock.readText.mockResolvedValue('user typed something else');
    await copy('secret');

    await vi.advanceTimersByTimeAsync(30_000);
    await flushMicrotasks();

    expect(clipboardMock.writeText).toHaveBeenCalledTimes(1);
    expect(clipboardMock.writeText).not.toHaveBeenCalledWith('');
  });

  it('resets the 30s window when the same text is copied again (A3)', async () => {
    await copy('secret');

    // Second copy 20s later: the first timer must be cancelled so the
    // original 30s mark cannot wipe the freshly copied secret.
    await vi.advanceTimersByTimeAsync(20_000);
    await copy('secret');

    // 35s after the FIRST copy but only 15s after the second: nothing fires.
    await vi.advanceTimersByTimeAsync(15_000);
    await flushMicrotasks();
    expect(clipboardMock.readText).not.toHaveBeenCalled();
    expect(clipboardMock.writeText).toHaveBeenCalledTimes(2);

    // 30s after the second copy: the clear runs once.
    await vi.advanceTimersByTimeAsync(15_000);
    await flushMicrotasks();
    expect(clipboardMock.readText).toHaveBeenCalledTimes(1);
    expect(clipboardMock.writeText).toHaveBeenCalledTimes(3);
    expect(clipboardMock.writeText).toHaveBeenLastCalledWith('');
  });
});
