export type UserRole = 'admin' | 'user';

export interface User {
  id: string;
  username: string;
  email: string;
  role: UserRole;
  avatar?: string;
  status: 'active' | 'banned';
  createdAt: string;
}

export interface FileItem {
  id: string;
  shortId?: string;
  originalName: string;
  filename: string;
  filePath: string;
  fileSize: number; // bytes
  mimeType: string;
  category: string;
  uploaderId: string;
  ownerUid?: string;
  uploaderName: string;
  description?: string;
  tags?: string[];
  isPasswordProtected: boolean;
  password?: string;
  isDraft: boolean;
  isFeatured: boolean;
  scheduledAt?: string | null;
  downloadsCount: number;
  viewsCount: number;
  thumbnailPath?: string;
  storageType: 'local' | 'r2' | 's3' | 'gdrive' | 'dropbox' | 'onedrive' | 'google_drive' | 'github' | 'mediafire' | 'external_link';
  driveFileId?: string;
  driveViewUrl?: string;
  driveDownloadUrl?: string;
  externalUrl?: string;
  ratingAvg: number;
  ratingCount: number;
  createdAt: string;
  updatedAt: string;
}

export interface Category {
  id: string;
  name: string;
  slug: string;
  description: string;
  icon: string; // Lucide icon name or emoji
  fileCount: number;
  createdAt: string;
}

export interface DownloadLog {
  id: string;
  fileId: string;
  fileName: string;
  userId?: string;
  visitorId?: string;
  userName?: string;
  ipAddress: string;
  userAgent: string;
  downloadedAt: string;
  durationSeconds?: number;
}

export type AdType =
  | 'banner'
  | 'native'
  | 'sticky'
  | 'popunder'
  | 'smartlink'
  | 'socialbar'
  | 'interstitial'
  | 'popup';

export interface Advertisement {
  id: string;
  title: string;
  type: AdType;
  code: string; // HTML or JS code
  location: string;
  isEnabled: boolean;
  clicks: number;
  impressions: number;
  createdAt: string;
}

export interface Comment {
  id: string;
  fileId: string;
  userId: string;
  userName: string;
  userAvatar?: string;
  comment: string;
  rating?: number;
  createdAt: string;
}

export interface Rating {
  id: string;
  fileId: string;
  userId: string;
  score: number;
  createdAt: string;
}

export interface Report {
  id: string;
  fileId: string;
  fileName: string;
  userId?: string;
  reason: 'broken_link' | 'virus_malware' | 'copyright' | 'inappropriate' | 'other';
  details: string;
  status: 'pending' | 'resolved' | 'dismissed';
  createdAt: string;
}

export interface Notification {
  id: string;
  userId: string;
  title: string;
  message: string;
  isRead: boolean;
  type: 'info' | 'success' | 'warning' | 'report';
  createdAt: string;
}

export interface WebsiteSettings {
  siteName: string;
  siteDescription: string;
  maxUploadSizeMb: number;
  allowedExtensions: string[];
  storageProvider: 'local' | 'r2' | 's3' | 'gdrive' | 'dropbox' | 'onedrive' | 'github';
  enableCaptcha: boolean;
  requireLoginToDownload: boolean;
  defaultDownloadTimer: number; // in seconds
  adFrequency: number;
  currencySymbol: string;
  analyticsCode: string;
  maintenanceMode: boolean;
  headerNotice: string;
  theme: 'dark' | 'light' | 'system';
  whatsappNumber?: string;
  telegramChannelUrl?: string;
  supportEmail?: string;
  gdriveFolderId?: string;
  gdriveClientId?: string;
  gdriveClientSecret?: string;
  gdriveRefreshToken?: string;
  gdriveClientEmail?: string;
  gdrivePrivateKey?: string;
  githubToken?: string;
  githubRepo?: string;
  githubTag?: string;
}

export interface ActivityLog {
  id: string;
  userId?: string;
  username: string;
  action: string;
  ip: string;
  details: string;
  createdAt: string;
}

export interface AuthState {
  user: User | null;
  token: string | null;
}

export interface AdminStats {
  totalFiles: number;
  totalDownloads: number;
  totalUsers: number;
  todayDownloads: number;
  onlineUsers: number;
  storageUsedBytes: number;
  revenueEstimate: number;
  recentUploads: FileItem[];
  recentDownloads: DownloadLog[];
  dailyDownloadsChart: { date: string; downloads: number; uploads: number }[];
}

export function getCleanFileName(name?: string): string {
  if (!name) return 'file';
  // Remove slash, backslash, question mark, hash, percent, etc., replace spaces with hyphens
  const clean = name.trim().replace(/[\/\\?#%*:|"<>]+/g, '').replace(/\s+/g, '-');
  return clean || 'file';
}

export function getCleanSlug(name?: string): string {
  return getCleanFileName(name);
}

export function getShortId(file: { id: string; shortId?: string }): string {
  if (file.shortId) return file.shortId;
  const id = file.id || '';
  if (id.includes('-')) {
    const parts = id.split('-');
    const lastPart = parts[parts.length - 1];
    if (lastPart && lastPart.length >= 3) return lastPart;
  }
  const cleanId = id.replace(/[^a-zA-Z0-9]/g, '');
  return cleanId.slice(-6) || 'file';
}

export function getShareableDownloadUrl(file: { id: string; shortId?: string; originalName?: string; filename?: string }): string {
  const origin = typeof window !== 'undefined' ? window.location.origin : '';
  const shortId = getShortId(file);
  const fileName = getCleanFileName(file.originalName || file.filename);
  return `${origin}/${shortId}-${fileName}`;
}
