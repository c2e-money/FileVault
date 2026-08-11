import fs from 'fs';
import path from 'path';
import { db } from './db.js';

function getGitHubConfig(overrides?: { token?: string; repo?: string; tag?: string }) {
  const database = db.getDb();
  const settings: any = database?.settings || {};

  const rawToken = overrides?.token !== undefined ? overrides.token : (settings.githubToken || process.env.GITHUB_TOKEN || process.env.GH_TOKEN || '');
  const rawRepo = overrides?.repo !== undefined ? overrides.repo : (settings.githubRepo || process.env.GITHUB_REPO || '');
  const rawTag = overrides?.tag !== undefined ? overrides.tag : (settings.githubTag || process.env.GITHUB_TAG || 'uploads');

  const token = (rawToken || '').trim();
  const repo = (rawRepo || '').trim();
  const tag = (rawTag || '').trim() || 'uploads';

  let owner = '';
  let repoName = '';

  if (repo && repo.includes('/')) {
    const parts = repo.split('/');
    owner = parts[0].trim();
    repoName = parts[1].trim();
  }

  return {
    token,
    repo,
    owner,
    repoName,
    tag,
  };
}

export function isGitHubConfigured(): boolean {
  const cfg = getGitHubConfig();
  return Boolean(cfg.token && cfg.owner && cfg.repoName);
}

export async function testGitHubConnection(overrides?: { token?: string; repo?: string; tag?: string }): Promise<{ status: 'CONNECTED' | 'ERROR'; repo?: string; message?: string; error?: string }> {
  const cfg = getGitHubConfig(overrides);

  if (!cfg.token) {
    return { status: 'ERROR', error: 'GitHub Personal Access Token (PAT) is missing.' };
  }
  if (!cfg.owner || !cfg.repoName) {
    return { status: 'ERROR', error: 'GitHub Repository format should be owner/repo (e.g. username/my-files).' };
  }

  try {
    const res = await fetch(`https://api.github.com/repos/${cfg.owner}/${cfg.repoName}`, {
      headers: {
        'Authorization': `Bearer ${cfg.token}`,
        'User-Agent': 'FileVault-App',
        'Accept': 'application/vnd.github.v3+json',
      },
    });

    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      return {
        status: 'ERROR',
        error: `GitHub API error (${res.status}): ${errData.message || res.statusText}. Please verify your token has 'repo' or 'contents: write' scope.`,
      };
    }

    const repoData = await res.json();
    return {
      status: 'CONNECTED',
      repo: repoData.full_name,
      message: `Successfully connected to repository ${repoData.full_name}! Releases tag '${cfg.tag}' ready for direct asset uploads.`,
    };
  } catch (err: any) {
    return {
      status: 'ERROR',
      error: err.message || 'Failed to connect to GitHub API.',
    };
  }
}

async function ensureRepoInitialized(cfg: ReturnType<typeof getGitHubConfig>, headers: Record<string, string>): Promise<void> {
  try {
    const repoRes = await fetch(`https://api.github.com/repos/${cfg.owner}/${cfg.repoName}`, { headers });
    if (repoRes.ok) {
      const repoData = await repoRes.json();
      // If default_branch is null or repo is empty (size 0 and no default branch commits)
      if (repoData.size === 0 || !repoData.default_branch) {
        console.log(`Repository ${cfg.owner}/${cfg.repoName} appears empty. Initializing with README.md...`);
        await fetch(`https://api.github.com/repos/${cfg.owner}/${cfg.repoName}/contents/README.md`, {
          method: 'PUT',
          headers: {
            ...headers,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            message: 'Initialize FileVault Storage Repository',
            content: Buffer.from('# FileVault Storage Repository\nAutomated cloud file storage container.').toString('base64'),
          }),
        });
      }
    }
  } catch (err) {
    console.warn('Repo initialization check note:', err);
  }
}

async function getOrCreateReleaseId(cfg: ReturnType<typeof getGitHubConfig>): Promise<{ id: number; uploadUrl: string }> {
  const headers = {
    'Authorization': `Bearer ${cfg.token}`,
    'User-Agent': 'FileVault-App',
    'Accept': 'application/vnd.github.v3+json',
  };

  // Ensure repository has an initial commit so tag/release creation won't fail with 422
  await ensureRepoInitialized(cfg, headers);

  // 1. Try fetching existing release by exact tag
  const tagRes = await fetch(`https://api.github.com/repos/${cfg.owner}/${cfg.repoName}/releases/tags/${encodeURIComponent(cfg.tag)}`, {
    headers,
  });

  if (tagRes.ok) {
    const releaseData = await tagRes.json();
    return {
      id: releaseData.id,
      uploadUrl: releaseData.upload_url,
    };
  }

  // 2. Fallback: Check if ANY release already exists in the repository
  try {
    const listRes = await fetch(`https://api.github.com/repos/${cfg.owner}/${cfg.repoName}/releases?per_page=10`, { headers });
    if (listRes.ok) {
      const releasesList = await listRes.json();
      if (Array.isArray(releasesList) && releasesList.length > 0) {
        const existingRel = releasesList[0];
        if (existingRel?.upload_url) {
          return {
            id: existingRel.id,
            uploadUrl: existingRel.upload_url,
          };
        }
      }
    }
  } catch (err) {
    console.warn('Failed to fetch existing releases list:', err);
  }

  // 3. Create new release if tag does not exist
  const createRes = await fetch(`https://api.github.com/repos/${cfg.owner}/${cfg.repoName}/releases`, {
    method: 'POST',
    headers: {
      ...headers,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      tag_name: cfg.tag,
      name: `Permanent Storage Release (${cfg.tag})`,
      body: 'Automated release container for permanent file assets uploaded via FileVault.',
      draft: false,
      prerelease: false,
    }),
  });

  if (!createRes.ok) {
    const errJson = await createRes.json().catch(() => ({}));
    const subError = errJson.errors?.[0]?.code || errJson.errors?.[0]?.message || '';

    // If 422 Validation Failed (e.g., tag already exists in Git or invalid tag), retry with fallback tag name
    if (createRes.status === 422) {
      const fallbackTag = `uploads-v${Date.now()}`;
      console.log(`Release creation with tag '${cfg.tag}' failed (422). Retrying with fallback tag '${fallbackTag}'...`);

      const retryRes = await fetch(`https://api.github.com/repos/${cfg.owner}/${cfg.repoName}/releases`, {
        method: 'POST',
        headers: {
          ...headers,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          tag_name: fallbackTag,
          name: `Permanent Storage Release (${fallbackTag})`,
          body: 'Automated release container for permanent file assets uploaded via FileVault.',
          draft: false,
          prerelease: false,
        }),
      });

      if (retryRes.ok) {
        const retryRelease = await retryRes.json();
        return {
          id: retryRelease.id,
          uploadUrl: retryRelease.upload_url,
        };
      }
    }

    const detailMsg = subError ? ` (${subError})` : '';
    throw new Error(`Failed to create GitHub release tag '${cfg.tag}': ${errJson.message || createRes.statusText}${detailMsg}`);
  }

  const newRelease = await createRes.json();
  return {
    id: newRelease.id,
    uploadUrl: newRelease.upload_url,
  };
}

export async function uploadToGitHubRelease(
  localFilePath: string,
  originalName: string,
  mimeType: string
): Promise<{ downloadUrl: string; assetId: number; size: number }> {
  const cfg = getGitHubConfig();

  if (!cfg.token || !cfg.owner || !cfg.repoName) {
    throw new Error('GitHub Releases Storage is not configured. Please enter Token and Repository in Admin Settings.');
  }

  if (!fs.existsSync(localFilePath)) {
    throw new Error(`Local file not found for GitHub upload: ${localFilePath}`);
  }

  const { uploadUrl } = await getOrCreateReleaseId(cfg);

  // Sanitize asset name for GitHub asset URL
  const ext = path.extname(originalName);
  const baseName = path.basename(originalName, ext).replace(/[^a-zA-Z0-9_\-]/g, '_');
  const sanitizedName = `${baseName}_${Date.now()}${ext}`;

  // Read binary file data
  const fileData = fs.readFileSync(localFilePath);
  const fileSize = fileData.length;

  // Clean template from GitHub upload_url: "https://uploads.github.com/.../assets{?name,label}"
  const cleanUploadUrl = uploadUrl.replace(/\{.*?\}/, '') + `?name=${encodeURIComponent(sanitizedName)}`;

  const uploadRes = await fetch(cleanUploadUrl, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${cfg.token}`,
      'User-Agent': 'FileVault-App',
      'Content-Type': mimeType || 'application/octet-stream',
      'Content-Length': fileSize.toString(),
    },
    body: fileData,
  });

  if (!uploadRes.ok) {
    const errJson = await uploadRes.json().catch(() => ({}));
    throw new Error(`GitHub Asset Upload failed (${uploadRes.status}): ${errJson.message || uploadRes.statusText}`);
  }

  const assetData = await uploadRes.json();

  // Safely cleanup temporary local disk file after successful upload to GitHub
  try {
    if (fs.existsSync(localFilePath)) {
      fs.unlinkSync(localFilePath);
    }
  } catch (err) {
    console.error('Failed to remove temp file after GitHub upload:', err);
  }

  return {
    downloadUrl: assetData.browser_download_url,
    assetId: assetData.id,
    size: assetData.size || fileSize,
  };
}

export async function deleteFromGitHubRelease(assetId: number): Promise<boolean> {
  const cfg = getGitHubConfig();
  if (!cfg.token || !cfg.owner || !cfg.repoName) return false;

  try {
    const res = await fetch(`https://api.github.com/repos/${cfg.owner}/${cfg.repoName}/releases/assets/${assetId}`, {
      method: 'DELETE',
      headers: {
        'Authorization': `Bearer ${cfg.token}`,
        'User-Agent': 'FileVault-App',
      },
    });
    return res.ok || res.status === 404;
  } catch {
    return false;
  }
}

export async function streamGitHubFileAsset(file: any, req: any, res: any): Promise<boolean> {
  const cfg = getGitHubConfig();
  const ghToken = cfg.token;
  const targetUrl = file.externalUrl || (file.filePath && (file.filePath.startsWith('http://') || file.filePath.startsWith('https://')) ? file.filePath : null);

  if (!targetUrl && !file.githubAssetId) {
    return false;
  }

  const mimeType = file.mimeType || 'application/octet-stream';
  const rawDisplayName = (req.query?.name as string) || file.originalName || file.filename || 'download_asset';
  const safeDisplayName = rawDisplayName.replace(/["\r\n\/\\]/g, '_');
  const encodedDisplayName = encodeURIComponent(rawDisplayName);

  const resHeaders: Record<string, any> = {
    'Content-Type': mimeType,
    'Content-Disposition': `attachment; filename="${safeDisplayName}"; filename*=UTF-8''${encodedDisplayName}`,
    'X-Content-Type-Options': 'nosniff',
  };

  const pipeResponseBufferToRes = async (remoteRes: Response) => {
    const contentLength = remoteRes.headers.get('content-length');
    if (contentLength) {
      resHeaders['Content-Length'] = contentLength;
    }
    const contentRange = remoteRes.headers.get('content-range');
    if (contentRange) {
      resHeaders['Content-Range'] = contentRange;
      resHeaders['Accept-Ranges'] = 'bytes';
      res.writeHead(206, resHeaders);
    } else {
      res.writeHead(200, resHeaders);
    }
    const arrayBuf = await remoteRes.arrayBuffer();
    const buffer = Buffer.from(arrayBuf);
    res.end(buffer);
  };

  // Strategy 1: Asset API if assetId and token/repo are available
  if (file.githubAssetId && cfg.owner && cfg.repoName && ghToken) {
    try {
      const assetApiUrl = `https://api.github.com/repos/${cfg.owner}/${cfg.repoName}/releases/assets/${file.githubAssetId}`;
      const apiRes = await fetch(assetApiUrl, {
        headers: {
          'Authorization': `Bearer ${ghToken}`,
          'User-Agent': 'FileDock-App',
          'Accept': 'application/octet-stream',
        },
        redirect: 'manual',
      });

      if (apiRes.status === 302 || apiRes.status === 301 || apiRes.status === 307) {
        const redirectUrl = apiRes.headers.get('location');
        if (redirectUrl) {
          const s3Res = await fetch(redirectUrl);
          if (s3Res.ok) {
            await pipeResponseBufferToRes(s3Res);
            return true;
          }
        }
      } else if (apiRes.ok) {
        await pipeResponseBufferToRes(apiRes);
        return true;
      }
    } catch (err) {
      console.error('GitHub Asset API stream error:', err);
    }
  }

  // Strategy 2: Direct public fetch with redirect follow (for public release assets)
  if (targetUrl) {
    try {
      const publicRes = await fetch(targetUrl, {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        },
        redirect: 'follow',
      });

      if (publicRes.ok) {
        await pipeResponseBufferToRes(publicRes);
        return true;
      }
    } catch (err) {
      console.error('GitHub public targetUrl stream error:', err);
    }

    // Strategy 3: Authenticated fetch with manual redirect (for private repo release assets)
    if (ghToken && targetUrl.includes('github')) {
      try {
        const authRes = await fetch(targetUrl, {
          headers: {
            'Authorization': `Bearer ${ghToken}`,
            'User-Agent': 'FileDock-App',
          },
          redirect: 'manual',
        });

        if (authRes.status === 302 || authRes.status === 301 || authRes.status === 307) {
          const redirUrl = authRes.headers.get('location');
          if (redirUrl) {
            const finalRes = await fetch(redirUrl);
            if (finalRes.ok) {
              await pipeResponseBufferToRes(finalRes);
              return true;
            }
          }
        } else if (authRes.ok) {
          await pipeResponseBufferToRes(authRes);
          return true;
        }
      } catch (err) {
        console.error('GitHub auth targetUrl stream error:', err);
      }
    }
  }

  return false;
}
