import { APIGatewayProxyEvent } from 'aws-lambda';

export type Role = 'admin' | 'operator' | 'viewer';

export interface AuthContext {
  userId: string;
  role: Role;
  email: string;
}

export const ROLE_PERMISSIONS: Record<Role, Set<string>> = {
  admin: new Set([
    'GET_RESOURCES',
    'POST_BULK_IMPORT',
    'CREATE_RECORD',
    'UPDATE_RECORD',
    'DELETE_RECORD',
    'VALIDATE_DATA',
    'EXPORT_DATA',
    'APPROVE_RECORD',
  ]),
  operator: new Set([
    'GET_RESOURCES',
    'POST_BULK_IMPORT',
    'CREATE_RECORD',
    'UPDATE_RECORD',
    'VALIDATE_DATA',
    'EXPORT_DATA',
  ]),
  viewer: new Set([
    'GET_RESOURCES',
  ]),
};

export function extractAuthContext(event: APIGatewayProxyEvent): AuthContext {
  const authHeader = event.headers['Authorization'] || '';
  const token = authHeader.replace('Bearer ', '');
  
  // Mock JWT parsing - in production, use proper JWT verification
  try {
    const decoded = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
    return {
      userId: decoded.sub || 'unknown',
      role: (decoded.role || 'viewer') as Role,
      email: decoded.email || 'unknown@example.com',
    };
  } catch {
    return {
      userId: 'unknown',
      role: 'viewer',
      email: 'unknown@example.com',
    };
  }
}

export function hasPermission(role: Role, permission: string): boolean {
  return ROLE_PERMISSIONS[role]?.has(permission) || false;
}

export function requirePermission(role: Role, permission: string): void {
  if (!hasPermission(role, permission)) {
    throw new Error(`FORBIDDEN: ${permission}`);
  }
}