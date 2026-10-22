import { randomBytes, scrypt as scryptCallback, timingSafeEqual, createHash, createHmac } from 'node:crypto';
import { promisify } from 'node:util';
const scrypt = promisify(scryptCallback);
export class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}
export function requireValue(condition, status = 400, message = 'Invalid request.') {
  if (!condition) throw new HttpError(status, message);
}
export const token = () => randomBytes(32).toString('hex');
export const digest = value => createHash('sha256').update(value).digest('hex');
export const rateKey = (secret, value) => createHmac('sha256', secret).update(value).digest('hex');
export function equal(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const left = Buffer.from(a), right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}
export async function hashPassword(password, salt = randomBytes(16).toString('hex')) {
  const key = await scrypt(password, salt, 64, { N: 32768, r: 8, p: 3, maxmem: 64 * 1024 * 1024 });
  return `scrypt$${salt}$${key.toString('hex')}`;
}
export async function verifyPassword(password, encoded) {
  const [, salt] = encoded.split('$');
  return equal(await hashPassword(password, salt), encoded);
}
export function fields(input, allowed) {
  requireValue(input && typeof input === 'object' && !Array.isArray(input));
  requireValue(Object.keys(input).every(key => allowed.includes(key)), 400, 'Unexpected field.');
}
export function text(input, min, max) {
  requireValue(typeof input === 'string' && input.trim().length >= min && input.length <= max && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/u.test(input));
  return input.trim();
}
export function email(input) {
  const result = text(input, 3, 254).toLowerCase();
  requireValue(/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(result), 400, 'Enter a valid email address.');
  return result;
}
export function password(input) {
  requireValue(typeof input === 'string' && input.length >= 15 && input.length <= 128, 400, 'Use a password of 15–128 characters.');
  return input;
}
export function choice(value, allowed) { requireValue(allowed.includes(value)); return value; }
export const attachmentTypes = {
  png: { type: 'image/png', magic: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a] },
  jpg: { type: 'image/jpeg', magic: [0xff, 0xd8, 0xff] },
  pdf: { type: 'application/pdf', magic: [0x25, 0x50, 0x44, 0x46, 0x2d] },
  txt: { type: 'text/plain; charset=utf-8' },
  csv: { type: 'text/csv; charset=utf-8' }
};
export function attachment(input, maxBytes) {
  requireValue(input && typeof input.name === 'string' && typeof input.data === 'string', 400, 'Attachment name and data are required.');
  const name = text(input.name, 1, 120);
  requireValue(!/[\\/]|\.\./.test(name), 400, 'File names must be simple.');
  const extension = name.toLowerCase().match(/\.(png|jpe?g|pdf|txt|csv)$/)?.[1]?.replace('jpeg', 'jpg');
  requireValue(extension, 400, 'Allowed file types: png, jpg, pdf, txt, csv.');
  requireValue(!/%[0-9a-f]{2}/i.test(name), 400, 'File names must be simple.');
  requireValue(input.data.length % 4 === 0 && input.data.length <= Math.ceil(maxBytes / 3) * 4, 400, 'Attachment exceeds the 3 MB limit.');
  requireValue(/^[A-Za-z0-9+/]+={0,2}$/.test(input.data), 400, 'Attachment data must be base64.');
  const bytes = Buffer.from(input.data, 'base64');
  requireValue(bytes.length >= 1 && bytes.length <= maxBytes, 400, 'Attachment exceeds the 3 MB limit.');
  const entry = attachmentTypes[extension];
  if (entry.magic) {
    for (let index = 0; index < entry.magic.length; index++) requireValue(bytes[index] === entry.magic[index], 400, 'The file contents do not match its extension.');
  } else {
    requireValue(!bytes.includes(0) && bytes.length <= maxBytes, 400, 'Only UTF-8 text files are accepted.');
    try { new TextDecoder('utf-8', { fatal: true }).decode(bytes); }
    catch { throw new HttpError(400, 'Only UTF-8 text files are accepted.'); }
  }
  return { name, type: entry.type, bytes };
}
export function uuid(value) { requireValue(typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)); return value; }
export function mayRead(user, ticket) {
  return user.role === 'admin' || user.id === ticket.owner_id || (user.role === 'staff' && user.id === ticket.assigned_to);
}
export function sessionCookie(value, production, clear = false) {
  return `${production ? '__Host-campus' : 'campus_dev'}=${value}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${clear ? 0 : 28800}${production ? '; Secure' : ''}`;
}
export function readCookie(header, production) {
  const name = production ? '__Host-campus' : 'campus_dev';
  const matches = (header || '').split(';').map(v => v.trim()).filter(v => v.startsWith(`${name}=`));
  if (matches.length !== 1) return null;
  const value = matches[0].slice(name.length + 1);
  return /^[0-9a-f]{64}$/.test(value) ? value : null;
}
export const headers = {
  'Content-Type': 'application/json; charset=utf-8',
  'Cache-Control': 'no-store',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
  'X-Frame-Options': 'DENY',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()'
};
