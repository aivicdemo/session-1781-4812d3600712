import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import {
  DynamoDBDocumentClient,
  GetCommand,
  ScanCommand,
  QueryCommand,
  PutCommand,
  UpdateCommand,
  DeleteCommand,
  BatchWriteCommand,
} from '@aws-sdk/lib-dynamodb';
import { randomUUID } from 'crypto';
import {
  extractAuthContext,
  requirePermission,
  ForbiddenError,
  NotFoundError,
  ValidationError,
} from './rbac';

const client = new DynamoDBClient({ region: process.env.AWS_REGION || 'ap-northeast-1' });
const docClient = DynamoDBDocumentClient.from(client);
const TABLE_NAME = process.env.MAIN_TABLE || 'SalesDataQualitySystem';

const TABLE_INDICES: Record<number, string> = {
  0: 'SalesData',
  1: 'SalesDataValidationRule',
  2: 'SalesDataAnomalyDetectionLog',
  3: 'BillingTargetItemDefinition',
  4: 'CustomerBillingAggregation',
  5: 'ServiceBillingAggregation',
  6: 'SalesDataMetadata',
  7: 'MonthlySummaryTemplate',
  8: 'DataQualityValidationResult',
  9: 'MissingDataNotificationLog',
  10: 'User',
  11: 'OperationHistory',
};

interface AuditLogEntry {
  pk: string;
  sk: string;
  userId: string;
  operationType: string;
  targetTable: string;
  targetRecordId?: string;
  operationContent: string;
  operationStatus: string;
  timestamp: number;
  createdAt: string;
}

async function createAuditLog(
  userId: string,
  operationType: string,
  targetTable: string,
  targetRecordId: string | undefined,
  operationContent: string,
  operationStatus: string
): Promise<void> {
  const now = new Date();
  const auditEntry: AuditLogEntry = {
    pk: 'AUDIT',
    sk: `${now.getTime()}#${randomUUID()}`,
    userId,
    operationType,
    targetTable,
    targetRecordId,
    operationContent,
    operationStatus,
    timestamp: now.getTime(),
    createdAt: now.toISOString(),
  };

  await docClient.send(
    new PutCommand({
      TableName: TABLE_NAME,
      Item: auditEntry,
    })
  );
}

function validateRequiredFields(item: Record<string, unknown>, requiredFields: string[]): void {
  for (const field of requiredFields) {
    if (item[field] === undefined || item[field] === null || item[field] === '') {
      throw new ValidationError(`Required field missing: ${field}`);
    }
  }
}

function addTimestamps(item: Record<string, unknown>, isUpdate: boolean = false): Record<string, unknown> {
  const now = new Date().toISOString();
  if (!isUpdate) {
    item.id = item.id || randomUUID();
    item.createdAt = item.createdAt || now;
  }
  item.updatedAt = now;
  return item;
}

async function handleGetResources(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  try {
    const authContext = extractAuthContext(event);
    requirePermission(authContext.role, 'GET_RESOURCES');

    const result = await docClient.send(
      new ScanCommand({
        TableName: TABLE_NAME,
        Limit: 100,
      })
    );

    return {
      statusCode: 200,
      body: JSON.stringify({
        items: result.Items || [],
        count: result.Count || 0,
      }),
    };
  } catch (error) {
    if (error instanceof ForbiddenError) {
      return {
        statusCode: 403,
        body: JSON.stringify({ error: error.message }),
      };
    }
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'Internal server error' }),
    };
  }
}

async function handleBulkImport(
  event: APIGatewayProxyEvent,
  tableIndex: number
): Promise<APIGatewayProxyResult> {
  try {
    const authContext = extractAuthContext(event);
    requirePermission(authContext.role, 'POST_BULK_IMPORT');

    const body = JSON.parse(event.body || '{}');
    const items: Record<string, unknown>[] = body.items || [];

    if (!Array.isArray(items) || items.length === 0) {
      throw new ValidationError('Items must be a non-empty array');
    }

    const tableName = TABLE_INDICES[tableIndex];
    if (!tableName) {
      throw new ValidationError(`Invalid table index: ${tableIndex}`);
    }

    const processedItems = items.map((item) => addTimestamps(item));
    const chunks: Record<string, unknown>[][] = [];

    for (let i = 0; i < processedItems.length; i += 25) {
      chunks.push(processedItems.slice(i, i + 25));
    }

    let imported = 0;
    let failed = 0;
    const errors: string[] = [];

    for (const chunk of chunks) {
      const requestItems: Record<string, unknown>[] = chunk.map((item) => ({
        PutRequest: {
          Item: item,
        },
      }));

      try {
        await docClient.send(
          new BatchWriteCommand({
            RequestItems: {
              [TABLE_NAME]: requestItems,
            },
          })
        );
        imported += chunk.length;
      } catch (chunkError) {
        failed += chunk.length;
        errors.push(`Batch write failed: ${(chunkError as Error).message}`);
      }
    }

    await createAuditLog(
      authContext.userId,
      'BULK_IMPORT',
      tableName,
      undefined,
      `Bulk imported ${imported} items to ${tableName}`,
      imported > 0 ? 'SUCCESS' : 'FAILURE'
    );

    return {
      statusCode: 200,
      body: JSON.stringify({
        imported,
        failed,
        errors,
      }),
    };
  } catch (error) {
    if (error instanceof ForbiddenError) {
      return {
        statusCode: 403,
        body: JSON.stringify({ error: error.message }),
      };
    }
    if (error instanceof ValidationError) {
      return {
        statusCode: 400,
        body: JSON.stringify({ error: error.message }),
      };
    }
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'Internal server error' }),
    };
  }
}

async function handleCreateRecord(
  event: APIGatewayProxyEvent,
  tableIndex: number
): Promise<APIGatewayProxyResult> {
  try {
    const authContext = extractAuthContext(event);
    requirePermission(authContext.role, 'CREATE_RECORD');

    const body = JSON.parse(event.body || '{}');
    const tableName = TABLE_INDICES[tableIndex];

    if (!tableName) {
      throw new ValidationError(`Invalid table index: ${tableIndex}`);
    }

    const item = addTimestamps({
      ...body,
      createdBy: authContext.userId,
      updatedBy: authContext.userId,
    });

    await docClient.send(
      new PutCommand({
        TableName: TABLE_NAME,
        Item: item,
      })
    );

    await createAuditLog(
      authContext.userId,
      'CREATE',
      tableName,
      item.id as string,
      `Created record in ${tableName}`,
      'SUCCESS'
    );

    return {
      statusCode: 201,
      body: JSON.stringify(item),
    };
  } catch (error) {
    if (error instanceof ForbiddenError) {
      return {
        statusCode: 403,
        body: JSON.stringify({ error: error.message }),
      };
    }
    if (error instanceof ValidationError) {
      return {
        statusCode: 400,
        body: JSON.stringify({ error: error.message }),
      };
    }
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'Internal server error' }),
    };
  }
}

async function handleUpdateRecord(
  event: APIGatewayProxyEvent,
  tableIndex: number
): Promise<APIGatewayProxyResult> {
  try {
    const authContext = extractAuthContext(event);
    requirePermission(authContext.role, 'UPDATE_RECORD');

    const recordId = event.pathParameters?.id;
    if (!recordId) {
      throw new ValidationError('Record ID is required');
    }

    const body = JSON.parse(event.body || '{}');
    const tableName = TABLE_INDICES[tableIndex];

    if (!tableName) {
      throw new ValidationError(`Invalid table index: ${tableIndex}`);
    }

    const updateData = addTimestamps(body, true);
    updateData.updatedBy = authContext.userId;

    const updateExpression = Object.keys(updateData)
      .map((key, index) => `${key} = :val${index}`)
      .join(', ');

    const expressionAttributeValues: Record<string, unknown> = {};
    Object.entries(updateData).forEach(([key, value], index) => {
      expressionAttributeValues[`:val${index}`] = value;
    });

    await docClient.send(
      new UpdateCommand({
        TableName: TABLE_NAME,
        Key: { id: recordId },
        UpdateExpression: `SET ${updateExpression}`,
        ExpressionAttributeValues: expressionAttributeValues,
      })
    );

    await createAuditLog(
      authContext.userId,
      'UPDATE',
      tableName,
      recordId,
      `Updated record in ${tableName}`,
      'SUCCESS'
    );

    return {
      statusCode: 200,
      body: JSON.stringify({ id: recordId, ...updateData }),
    };
  } catch (error) {
    if (error instanceof ForbiddenError) {
      return {
        statusCode: 403,
        body: JSON.stringify({ error: error.message }),
      };
    }
    if (error instanceof ValidationError) {
      return {
        statusCode: 400,
        body: JSON.stringify({ error: error.message }),
      };
    }
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'Internal server error' }),
    };
  }
}

async function handleDeleteRecord(
  event: APIGatewayProxyEvent,
  tableIndex: number
): Promise<APIGatewayProxyResult> {
  try {
    const authContext = extractAuthContext(event);
    requirePermission(authContext.role, 'DELETE_RECORD');

    const recordId = event.pathParameters?.id;
    if (!recordId) {
      throw new ValidationError('Record ID is required');
    }

    const tableName = TABLE_INDICES[tableIndex];
    if (!tableName) {
      throw new ValidationError(`Invalid table index: ${tableIndex}`);
    }

    await docClient.send(
      new DeleteCommand({
        TableName: TABLE_NAME,
        Key: { id: recordId },
      })
    );

    await createAuditLog(
      authContext.userId,
      'DELETE',
      tableName,
      recordId,
      `Deleted record from ${tableName}`,
      'SUCCESS'
    );

    return {
      statusCode: 204,
      body: '',
    };
  } catch (error) {
    if (error instanceof ForbiddenError) {
      return {
        statusCode: 403,
        body: JSON.stringify({ error: error.message }),
      };
    }
    if (error instanceof ValidationError) {
      return {
        statusCode: 400,
        body: JSON.stringify({ error: error.message }),
      };
    }
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'Internal server error' }),
    };
  }
}

async function handleGetRecord(
  event: APIGatewayProxyEvent,
  tableIndex: number
): Promise<APIGatewayProxyResult> {
  try {
    const authContext = extractAuthContext(event);
    requirePermission(authContext.role, 'GET_RESOURCES');

    const recordId = event.pathParameters?.id;
    if (!recordId) {
      throw new ValidationError('Record ID is required');
    }

    const result = await docClient.send(
      new GetCommand({
        TableName: TABLE_NAME,
        Key: { id: recordId },
      })
    );

    if (!result.Item) {
      throw new NotFoundError(`Record not found: ${recordId}`);
    }

    return {
      statusCode: 200,
      body: JSON.stringify(result.Item),
    };
  } catch (error) {
    if (error instanceof ForbiddenError) {
      return {
        statusCode: 403,
        body: JSON.stringify({ error: error.message }),
      };
    }
    if (error instanceof NotFoundError) {
      return {
        statusCode: 404,
        body: JSON.stringify({ error: error.message }),
      };
    }
    if (error instanceof ValidationError) {
      return {
        statusCode: 400,
        body: JSON.stringify({ error: error.message }),
      };
    }
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'Internal server error' }),
    };
  }
}

export async function handler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const path = event.path || '';
  const method = event.httpMethod || 'GET';

  try {
    if (path === '/resources' && method === 'GET') {
      return await handleGetResources(event);
    }

    const bulkMatch = path.match(/^\/api\/(\d+)\/bulk$/);
    if (bulkMatch && method === 'POST') {
      const tableIndex = parseInt(bulkMatch[1], 10);
      return await handleBulkImport(event, tableIndex);
    }

    const createMatch = path.match(/^\/api\/(\d+)$/);
    if (createMatch && method === 'POST') {
      const tableIndex = parseInt(createMatch[1], 10);
      return await handleCreateRecord(event, tableIndex);
    }

    const getMatch = path.match(/^\/api\/(\d+)\/([a-f0-9-]+)$/);
    if (getMatch && method === 'GET') {
      const tableIndex = parseInt(getMatch[1], 10);
      event.pathParameters = { id: getMatch[2] };
      return await handleGetRecord(event, tableIndex);
    }

    const updateMatch = path.match(/^\/api\/(\d+)\/([a-f0-9-]+)$/);
    if (updateMatch && method === 'PUT') {
      const tableIndex = parseInt(updateMatch[1], 10);
      event.pathParameters = { id: updateMatch[2] };
      return await handleUpdateRecord(event, tableIndex);
    }

    const deleteMatch = path.match(/^\/api\/(\d+)\/([a-f0-9-]+)$/);
    if (deleteMatch && method === 'DELETE') {
      const tableIndex = parseInt(deleteMatch[1], 10);
      event.pathParameters = { id: deleteMatch[2] };
      return await handleDeleteRecord(event, tableIndex);
    }

    return {
      statusCode: 404,
      body: JSON.stringify({ error: 'Not found' }),
    };
  } catch (error) {
    console.error('Unhandled error:', error);
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'Internal server error' }),
    };
  }
}