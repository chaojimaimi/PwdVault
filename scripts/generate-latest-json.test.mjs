// Tests for the updater feed generator core (scripts/generate-latest-json.mjs).
// Covers the PHASE-AU-PLAN D1.3 rules: platform mapping, skip-unsigned,
// asset URL assembly, empty-signature rejection, and the Contents API
// commit retry behaviour.
import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  buildLatestJson,
  collectAssets,
  commitFeed,
  feedTimestamp,
  fetchFeedSha,
  platformForAsset,
  releaseAssetUrl,
} from './generate-latest-json.mjs';

const SIG = 'dW50cnVzdGVkIGNvbW1lbnQ6IHNpZ25hdHVyZQo=';

describe('platformForAsset', () => {
  it('maps updater artifacts to tauri platform keys', () => {
    expect(platformForAsset('PwdVault.app.tar.gz')).toBe('darwin-aarch64');
    expect(platformForAsset('PwdVault_1.1.7_x64-setup.exe')).toBe('windows-x86_64');
  });

  it('ignores non-updater release assets', () => {
    expect(platformForAsset('PwdVault_1.1.7_aarch64.dmg')).toBeNull();
    expect(platformForAsset('PwdVault-Chrome-Extension-v1.1.7.zip')).toBeNull();
    expect(platformForAsset('SHA256SUMS')).toBeNull();
    expect(platformForAsset('PwdVault.app.tar.gz.sig')).toBeNull();
  });
});

describe('buildLatestJson', () => {
  const base = { version: '1.1.7', pubDate: '2026-09-18T12:00:00Z' };

  it('assembles signed platform entries with release download URLs', () => {
    const feed = buildLatestJson({
      ...base,
      assets: [
        { name: 'PwdVault.app.tar.gz', signature: SIG },
        { name: 'PwdVault_1.1.7_x64-setup.exe', signature: SIG },
        { name: 'PwdVault_1.1.7_aarch64.dmg' }, // ignored: not an updater artifact
      ],
    });
    expect(feed).toEqual({
      version: '1.1.7',
      pub_date: '2026-09-18T12:00:00Z',
      platforms: {
        'darwin-aarch64': {
          signature: SIG,
          url: 'https://github.com/chaojimaimi/PwdVault/releases/download/v1.1.7/PwdVault.app.tar.gz',
        },
        'windows-x86_64': {
          signature: SIG,
          url: 'https://github.com/chaojimaimi/PwdVault/releases/download/v1.1.7/PwdVault_1.1.7_x64-setup.exe',
        },
      },
    });
  });

  it('skips platforms whose artifact has no .sig (never publishes unsigned)', () => {
    const feed = buildLatestJson({
      ...base,
      assets: [
        { name: 'PwdVault.app.tar.gz' },
        { name: 'PwdVault_1.1.7_x64-setup.exe', signature: SIG },
      ],
    });
    expect(Object.keys(feed.platforms)).toEqual(['windows-x86_64']);
  });

  it('treats a whitespace-only .sig as missing', () => {
    const feed = buildLatestJson({
      ...base,
      assets: [
        { name: 'PwdVault.app.tar.gz', signature: '   \n  ' },
        { name: 'PwdVault_1.1.7_x64-setup.exe', signature: SIG },
      ],
    });
    expect(Object.keys(feed.platforms)).toEqual(['windows-x86_64']);
  });

  it('rejects an empty feed (no signed platform at all)', () => {
    expect(() =>
      buildLatestJson({ ...base, assets: [{ name: 'PwdVault.app.tar.gz' }] }),
    ).toThrow(/empty feed/);
  });

  it('rejects duplicate artifacts for the same platform', () => {
    expect(() =>
      buildLatestJson({
        ...base,
        assets: [
          { name: 'PwdVault.app.tar.gz', signature: SIG },
          { name: 'PwdVault.app.tar.gz', signature: SIG },
        ],
      }),
    ).toThrow(/duplicate/);
  });

  it('rejects non-semver versions', () => {
    expect(() => buildLatestJson({ ...base, version: 'v1.1.7', assets: [] })).toThrow(/invalid version/);
    expect(() => buildLatestJson({ ...base, version: 'banana', assets: [] })).toThrow(/invalid version/);
  });
});

describe('feedTimestamp', () => {
  it('emits RFC 3339 UTC without milliseconds', () => {
    expect(feedTimestamp(new Date('2026-09-18T12:00:00.000Z'))).toBe('2026-09-18T12:00:00Z');
  });
});

describe('collectAssets', () => {
  let dir;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'feed-assets-'));
  });
  afterAll(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('walks the artifact tree and picks up sibling .sig contents', () => {
    mkdirSync(join(dir, 'macos-artifacts'));
    writeFileSync(join(dir, 'macos-artifacts', 'PwdVault.app.tar.gz'), 'tar');
    writeFileSync(join(dir, 'macos-artifacts', 'PwdVault.app.tar.gz.sig'), SIG);
    mkdirSync(join(dir, 'windows-artifacts'));
    writeFileSync(join(dir, 'windows-artifacts', 'PwdVault_1.1.7_x64-setup.exe'), 'exe');
    writeFileSync(join(dir, 'SHA256SUMS'), 'hashes');

    const assets = collectAssets(dir);
    expect(assets).toHaveLength(2);
    const macos = assets.find((a) => a.name === 'PwdVault.app.tar.gz');
    expect(macos.signature).toBe(SIG);
    const win = assets.find((a) => a.name.endsWith('.exe'));
    expect(win.signature).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Contents API commit-back
// ---------------------------------------------------------------------------

function jsonResponse(status, body = {}) {
  return { ok: status < 400, status, json: async () => body };
}

describe('commitFeed / fetchFeedSha (Contents API)', () => {
  const feedJson = '{"version":"1.1.7"}';

  beforeEach(() => vi.restoreAllMocks());

  it('creates the feed without a sha when it does not exist yet', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse(404)) // GET → no existing feed
      .mockResolvedValueOnce(jsonResponse(201, { commit: { sha: 'abc' } })); // PUT
    vi.stubGlobal('fetch', fetchMock);

    const result = await commitFeed({ token: 't', contentJson: feedJson, message: 'msg [skip ci]' });

    expect(result.commit.sha).toBe('abc');
    const putBody = JSON.parse(fetchMock.mock.calls[1][1].body);
    expect(putBody.sha).toBeUndefined();
    expect(putBody.branch).toBe('main');
    expect(putBody.message).toContain('[skip ci]');
    expect(putBody.content).toBe(Buffer.from(feedJson, 'utf8').toString('base64'));
  });

  it('updates the feed with the current sha when it exists', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse(200, { sha: 'deadbeef' }))
      .mockResolvedValueOnce(jsonResponse(200, { commit: { sha: 'abc2' } }));
    vi.stubGlobal('fetch', fetchMock);

    await commitFeed({ token: 't', contentJson: feedJson, message: 'msg' });

    const putBody = JSON.parse(fetchMock.mock.calls[1][1].body);
    expect(putBody.sha).toBe('deadbeef');
  });

  it('retries on a racing writer (409) with a refreshed sha', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse(200, { sha: 'sha-1' }))
      .mockResolvedValueOnce(jsonResponse(409)) // race → conflict
      .mockResolvedValueOnce(jsonResponse(200, { sha: 'sha-2' }))
      .mockResolvedValueOnce(jsonResponse(200, { commit: { sha: 'done' } }));
    vi.stubGlobal('fetch', fetchMock);

    const result = await commitFeed({ token: 't', contentJson: feedJson, message: 'msg' });

    expect(result.commit.sha).toBe('done');
    const putBody = JSON.parse(fetchMock.mock.calls[3][1].body);
    expect(putBody.sha).toBe('sha-2');
  });

  it('gives up after three conflicting attempts', async () => {
    // Feed sha resolves fine; every PUT conflicts (another writer keeps winning).
    const fetchMock = vi.fn((_url, opts) => {
      if (opts?.method === 'PUT') return Promise.resolve(jsonResponse(409));
      return Promise.resolve(jsonResponse(200, { sha: 's' }));
    });
    vi.stubGlobal('fetch', fetchMock);

    await expect(
      commitFeed({ token: 't', contentJson: feedJson, message: 'msg', retries: 3 }),
    ).rejects.toThrow(/HTTP 409/);
    // 3 attempts, each = 1 sha GET + 1 PUT.
    expect(fetchMock).toHaveBeenCalledTimes(6);
  });

  it('retries when the sha went stale (422)', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse(200, { sha: 'stale' }))
      .mockResolvedValueOnce(jsonResponse(422)) // sha no longer matches
      .mockResolvedValueOnce(jsonResponse(200, { sha: 'fresh' }))
      .mockResolvedValueOnce(jsonResponse(200, { commit: { sha: 'ok' } }));
    vi.stubGlobal('fetch', fetchMock);

    await expect(
      commitFeed({ token: 't', contentJson: feedJson, message: 'msg' }),
    ).resolves.toMatchObject({ commit: { sha: 'ok' } });
  });
});

describe('fetchFeedSha', () => {
  it('returns null for a missing feed (404)', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(jsonResponse(404)));
    await expect(fetchFeedSha({ token: 't' })).resolves.toBeNull();
  });
});
