#!/usr/bin/env node
// ---------------------------------------------------------------------------
// Phase AU: updater feed generator (latest.json).
//
// Reads the release artifacts downloaded by the create-release job, builds the
// tauri-plugin-updater feed for the platforms that have a minisign `.sig`
// file, and optionally publishes it to the repo's default branch via the
// GitHub Contents API (avoids git-push races; commit message carries
// `[skip ci]` so the feed commit never re-triggers the release pipeline).
//
// Usage (CI):
//   node scripts/generate-latest-json.mjs \
//     --artifacts artifacts --version 1.1.7 --output dist/latest.json --commit
//
// Environment (only needed for --commit):
//   GITHUB_TOKEN  token with `contents: write` on the target repository.
//
// Feed schema (fixed by tauri-plugin-updater):
//   { version, pub_date, platforms: { "<platform>": { signature, url } } }
//
// Compatibility rule (PHASE-AU-PLAN D1.3): a platform without a non-empty
// `.sig` never enters the feed — an unsigned artifact can never be published
// as an update entry.
// ---------------------------------------------------------------------------

import { readdirSync, readFileSync, statSync, mkdirSync, writeFileSync } from 'node:fs';
import { join, basename } from 'node:path';
import { Buffer } from 'node:buffer';

export const DEFAULT_REPO = 'chaojimaimi/PwdVault';
export const FEED_PATH = 'latest.json';
export const API_BASE = 'https://api.github.com';
export const DOWNLOAD_URL_BASE = 'https://github.com';

/**
 * Map an updater artifact file name to its tauri platform key.
 * macOS: `*.app.tar.gz`; Windows: NSIS `*.exe`. Everything else (dmg, zips,
 * checksums, extension packages) maps to null and is ignored.
 */
export function platformForAsset(name) {
  if (name.endsWith('.app.tar.gz')) return 'darwin-aarch64';
  if (name.endsWith('.exe')) return 'windows-x86_64';
  return null;
}

/** GitHub Release asset direct link for a version's artifact. */
export function releaseAssetUrl(version, name, repo = DEFAULT_REPO) {
  return `${DOWNLOAD_URL_BASE}/${repo}/releases/download/v${version}/${encodeURIComponent(name)}`;
}

/**
 * Build the feed object from `{ name, signature? }` assets.
 * - signature must be the trimmed `.sig` contents; empty/missing means the
 *   platform is skipped (never published unsigned).
 * - two artifacts mapping to the same platform is a hard error (would mean a
 *   mis-assembled artifacts directory).
 * - zero signed platforms throws: an empty feed would strand every updater.
 */
export function buildLatestJson({ version, pubDate, assets }) {
  if (!/^\d+\.\d+\.\d+/.test(version)) {
    throw new Error(`invalid version: "${version}" (expected clean semver, no "v" prefix)`);
  }
  const platforms = {};
  for (const asset of assets) {
    const platform = platformForAsset(asset.name);
    if (!platform) continue;
    if (platforms[platform]) {
      throw new Error(`duplicate ${platform} updater artifact: ${asset.name}`);
    }
    const signature = (asset.signature ?? '').trim();
    if (!signature) continue; // no .sig → platform stays out of the feed
    platforms[platform] = { signature, url: releaseAssetUrl(version, asset.name) };
  }
  if (Object.keys(platforms).length === 0) {
    throw new Error('no signed updater artifacts found — refusing to publish an empty feed');
  }
  return { version, pub_date: pubDate, platforms };
}

/** RFC 3339 UTC timestamp without milliseconds (matches the feed examples). */
export function feedTimestamp(date = new Date()) {
  return date.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

/**
 * Walk `rootDir` (typ. the download-artifact tree) and collect
 * `{ name, path, signature }` for updater-relevant artifacts, where
 * `signature` is the contents of the sibling `<name>.sig` file when present.
 */
export function collectAssets(rootDir) {
  const assets = [];
  const walk = (dir) => {
    for (const entry of readdirSync(dir)) {
      const full = join(dir, entry);
      if (statSync(full).isDirectory()) {
        walk(full);
        continue;
      }
      const name = basename(full);
      if (!platformForAsset(name)) continue;
      let signature;
      try {
        signature = readFileSync(`${full}.sig`, 'utf8');
      } catch {
        signature = undefined; // .sig absent — keep the asset, skip platform
      }
      assets.push({ name, path: full, signature });
    }
  };
  walk(rootDir);
  return assets;
}

// ---------------------------------------------------------------------------
// GitHub Contents API (feed commit-back)
// ---------------------------------------------------------------------------

function apiHeaders(token) {
  return {
    Authorization: `Bearer ${token}`,
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
  };
}

/** Current blob sha of the feed on `branch`, or null when it does not exist. */
export async function fetchFeedSha({ token, repo = DEFAULT_REPO, branch = 'main', path = FEED_PATH }) {
  const res = await fetch(`${API_BASE}/repos/${repo}/contents/${path}?ref=${branch}`, {
    headers: apiHeaders(token),
  });
  if (res.status === 404) return null;
  if (!res.ok) {
    throw new Error(`GET contents/${path} failed: HTTP ${res.status}`);
  }
  const json = await res.json();
  return json.sha;
}

/**
 * Create/update the feed on `branch`. Re-fetches the sha and retries on
 * racing writers (HTTP 409 / stale-sha 422) up to `retries` attempts.
 * Returns the API response JSON of the successful PUT.
 */
export async function commitFeed({
  token,
  contentJson,
  message,
  repo = DEFAULT_REPO,
  branch = 'main',
  path = FEED_PATH,
  retries = 3,
}) {
  const content = Buffer.from(contentJson, 'utf8').toString('base64');
  let lastError;
  for (let attempt = 1; attempt <= retries; attempt++) {
    const sha = await fetchFeedSha({ token, repo, branch, path });
    const body = { message, content, branch };
    if (sha) body.sha = sha;
    const res = await fetch(`${API_BASE}/repos/${repo}/contents/${path}`, {
      method: 'PUT',
      headers: { ...apiHeaders(token), 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (res.ok) return res.json();
    lastError = new Error(`PUT contents/${path} failed: HTTP ${res.status}`);
    // 409 = conflict, 422 = sha no longer matches — another writer (or a
    // human commit) updated the feed first; refetch the sha and try again.
    if ((res.status === 409 || res.status === 422) && attempt < retries) {
      continue;
    }
    throw lastError;
  }
  throw lastError;
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i++) {
    const key = argv[i];
    if (!key.startsWith('--')) continue;
    const flag = key.slice(2);
    if (flag === 'commit') {
      args.commit = true;
    } else {
      args[flag] = argv[++i];
    }
  }
  return args;
}

async function main(argv) {
  const args = parseArgs(argv);
  if (!args.artifacts || !args.version) {
    console.error('usage: generate-latest-json.mjs --artifacts <dir> --version <semver> [--output <file>] [--commit] [--branch main] [--repo owner/name]');
    process.exit(2);
  }

  const assets = collectAssets(args.artifacts);
  const feed = buildLatestJson({ version: args.version, pubDate: feedTimestamp(), assets });
  const json = `${JSON.stringify(feed, null, 2)}\n`;

  const signed = Object.keys(feed.platforms).join(', ');
  console.log(`updater feed v${feed.version}: platforms [${signed || 'none'}]`);

  if (args.output) {
    mkdirSync(join(args.output, '..'), { recursive: true });
    writeFileSync(args.output, json, 'utf8');
    console.log(`wrote ${args.output}`);
  }

  if (args.commit) {
    const token = process.env.GITHUB_TOKEN;
    if (!token) {
      console.error('--commit requires GITHUB_TOKEN');
      process.exit(2);
    }
    const result = await commitFeed({
      token,
      contentJson: json,
      message: `chore(release): updater feed v${feed.version} [skip ci]`,
      repo: args.repo ?? DEFAULT_REPO,
      branch: args.branch ?? 'main',
    });
    console.log(`committed ${FEED_PATH} to ${args.branch ?? 'main'} @ ${result.commit?.sha?.slice(0, 12) ?? '?'}`);
  }

  if (!args.output && !args.commit) {
    process.stdout.write(json);
  }
}

// Run only when executed directly (not when imported by tests).
const isDirectRun = process.argv[1] && import.meta.url.endsWith(basename(process.argv[1]));
if (isDirectRun) {
  await main(process.argv.slice(2));
}
