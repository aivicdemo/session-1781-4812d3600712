import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import {
  DynamoDBClient,
  BatchWriteItemCommand,
  BatchWriteItemCommandInput,
} from '@aws-sdk/client-dynamodb';
import {
  DynamoDBDocumentClient,
  ScanCommand,
  QueryCommand,
  GetCommand,
  PutCommand,
  UpdateCommand,
  DeleteCommand,
} from '@aws-sdk/lib-dynamodb';
import { randomUUID } from 'crypto';
import { extractAuthContext, requirePermission, Role } from './rbac';

const client = new DynamoDBClient({ region: process.env.AWS_REGION || 'ap-northeast-1' });
const docClient = DynamoDBDocumentClient.from(client);
const TABLE_NAME = process.env.MAIN_TABLE || 'SalesDataQualityTable';

interface AuditLog {
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

interface BulkImportRequest {
  items: Record<string, unknown>[];
}

interface BulkImportResponse {
  imported: number;
  failed: number;
  errors: string[];
}

function createResponse(statusCode: number, body: unknown): APIGatewayProxyResult {
  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
    },
    body: JSON.stringify(body),
  };
}

async function createAuditLog(
  userId: string,
  operationType: string,
  targetTable: string,
  targetRecordId: string | undefined,
  operationContent: string,
  operationStatus: string
): Promise<void> {
  const auditLog: AuditLog = {
    pk: 'AUDIT',
    sk: `${Date.now()}#${randomUUID()}`,
    userId,
    operationType,
    targetTable,
    targetRecordId,
    operationContent,
    operationStatus,
    timestamp: Date.now(),
    createdAt: new Date().toISOString(),
  };

  await docClient.send(
    new PutCommand({
      TableName: TABLE_NAME,
      Item: auditLog,
    })
  );
}

async function handleGetResources(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  try {
    const authContext = extractAuthContext(event);
    requirePermission(authContext.role, 'GET_RESOURCES');

    const tableIndex = event.pathParameters?.tableIndex || '0';
    const tableMap: Record<string, string> = {
      '0': 'SalesData',
      '1': 'ValidationRules',
      '2': 'AnomalyDetectionLog',
      '3': 'BillingItemDefinition',
      '4': 'CustomerBillingAggregation',
      '5': 'ServiceBillingAggregation',
      '6': 'SalesDataMetadata',
      '7': 'MonthlySummaryTemplate',
      '8': 'DataQualityValidationResult',
      '9': 'MissingDataNotificationLog',
      '10': 'User',
      '11': 'OperationHistory',
    };

    const targetTable = tableMap[tableIndex];
    if (!targetTable) {
      return createResponse(400, { error: 'Invalid table index' });
    }

    const queryParams = event.queryStringParameters || {};
    const limit = parseInt(queryParams.limit || '100', 10);
    const exclusiveStartKey = queryParams.lastKey
      ? JSON.parse(Buffer.from(queryParams.lastKey, 'base64').toString())
      : undefined;

    const command = new ScanCommand({
      TableName: TABLE_NAME,
      Limit: limit,
      ExclusiveStartKey: exclusiveStartKey,
      FilterExpression: 'attribute_exists(#type)',
      ExpressionAttributeNames: {
        '#type': 'type',
      },
    });

    const result = await docClient.send(command);

    const nextKey = result.LastEvaluatedKey
      ? Buffer.from(JSON.stringify(result.LastEvaluatedKey)).toString('base64')
      : undefined;

    return createResponse(200, {
      items: result.Items || [],
      count: result.Count || 0,
      nextKey,
    });
  } catch (error) {
    if (error instanceof Error && error.message.includes('FORBIDDEN')) {
      return createResponse(403, { error: 'Access denied' });
    }
    console.error('Error in handleGetResources:', error);
    return createResponse(500, { error: 'Internal server error' });
  }
}

async function handleBulkImport(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  try {
    const authContext = extractAuthContext(event);
    requirePermission(authContext.role, 'POST_BULK_IMPORT');

    const tableIndex = event.pathParameters?.tableIndex || '0';
    const tableMap: Record<string, string> = {
      '0': 'SalesData',
      '1': 'ValidationRules',
      '2': 'AnomalyDetectionLog',
      '3': 'BillingItemDefinition',
      '4': 'CustomerBillingAggregation',
      '5': 'ServiceBillingAggregation',
      '6': 'SalesDataMetadata',
      '7': 'MonthlySummaryTemplate',
      '8': 'DataQualityValidationResult',
      '9': 'MissingDataNotificationLog',
      '10': 'User',
      '11': 'OperationHistory',
    };

    const targetTable = tableMap[tableIndex];
    if (!targetTable) {
      return createResponse(400, { error: 'Invalid table index' });
    }

    const body: BulkImportRequest = JSON.parse(event.body || '{}');
    if (!Array.isArray(body.items)) {
      return createResponse(400, { error: 'items must be an array' });
    }

    const items = body.items;
    const now = new Date().toISOString();
    const errors: string[] = [];
    let imported = 0;
    let failed = 0;

    // Process in batches of 25 (DynamoDB BatchWriteItem limit)
    const batchSize = 25;
    for (let i = 0; i < items.length; i += batchSize) {
      const batch = items.slice(i, i + batchSize);
      const writeRequests = batch.map((item) => ({
        PutRequest: {
          Item: {
            pk: { S: targetTable },
            sk: { S: `${item.id || randomUUID()}#${Date.now()}` },
            type: { S: targetTable },
            ...Object.entries(item).reduce(
              (acc, [key, value]) => {
                if (value === null || value === undefined) {
                  return acc;
                }
                if (typeof value === 'string') {
                  acc[key] = { S: value };
                } else if (typeof value === 'number') {
                  acc[key] = { N: value.toString() };
                } else if (typeof value === 'boolean') {
                  acc[key] = { BOOL: value };
                } else if (Array.isArray(value)) {
                  acc[key] = { L: value.map((v) => ({ S: String(v) })) };
                } else if (typeof value === 'object') {
                  acc[key] = { M: Object.entries(value).reduce((m, [k, v]) => {
                    m[k] = { S: String(v) };
                    return m;
                  }, {} as Record<string, { S: string }>) };
                }
                return acc;
              },
              {} as Record<string, unknown>
            ),
            createdAt: { S: now },
            updatedAt: { S: now },
            createdBy: { S: authContext.userId },
          },
        },
      }));

      const batchWriteParams: BatchWriteItemCommandInput = {
        RequestItems: {
          [TABLE_NAME]: writeRequests,
        },
      };

      try {
        const batchResult = await client.send(new BatchWriteItemCommand(batchWriteParams));
        imported += batch.length - (batchResult.UnprocessedItems?.[TABLE_NAME]?.length || 0);
        failed += batchResult.UnprocessedItems?.[TABLE_NAME]?.length || 0;

        if (batchResult.UnprocessedItems?.[TABLE_NAME]) {
          errors.push(
            `Batch ${Math.floor(i / batchSize) + 1}: ${batchResult.UnprocessedItems[TABLE_NAME].length} items failed to write`
          );
        }
      } catch (batchError) {
        failed += batch.length;
        errors.push(
          `Batch ${Math.floor(i / batchSize) + 1}: ${batchError instanceof Error ? batchError.message : 'Unknown error'}`
        );
      }
    }

    // Create audit log
    await createAuditLog(
      authContext.userId,
      'BULK_IMPORT',
      targetTable,
      undefined,
      `Bulk imported ${imported} items`,
      'SUCCESS'
    );

    const response: BulkImportResponse = {
      imported,
      failed,
      errors,
    };

    return createResponse(200, response);
  } catch (error) {
    if (error instanceof Error && error.message.includes('FORBIDDEN')) {
      return createResponse(403, { error: 'Access denied' });
    }
    console.error('Error in handleBulkImport:', error);
    return createResponse(500, { error: 'Internal server error' });
  }
}

async function handleCreateRecord(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  try {
    const authContext = extractAuthContext(event);
    requirePermission(authContext.role, 'CREATE_RECORD');

    const tableIndex = event.pathParameters?.tableIndex || '0';
    const tableMap: Record<string, string> = {
      '0': 'SalesData',
      '1': 'ValidationRules',
      '2': 'AnomalyDetectionLog',
      '3': 'BillingItemDefinition',
      '4': 'CustomerBillingAggregation',
      '5': 'ServiceBillingAggregation',
      '6': 'SalesDataMetadata',
      '7': 'MonthlySummaryTemplate',
      '8': 'DataQualityValidationResult',
      '9': 'MissingDataNotificationLog',
      '10': 'User',
      '11': 'OperationHistory',
    };

    const targetTable = tableMap[tableIndex];
    if (!targetTable) {
      return createResponse(400, { error: 'Invalid table index' });
    }

    const body = JSON.parse(event.body || '{}');
    const now = new Date().toISOString();
    const recordId = randomUUID();

    const item = {
      pk: targetTable,
      sk: `${recordId}#${Date.now()}`,
      id: recordId,
      type: targetTable,
      ...body,
      createdAt: now,
      updatedAt: now,
      createdBy: authContext.userId,
      updatedBy: authContext.userId,
    };

    await docClient.send(
      new PutCommand({
        TableName: TABLE_NAME,
        Item: item,
      })
    );

    await createAuditLog(
      authContext.userId,
      'CREATE',
      targetTable,
      recordId,
      `Created record: ${JSON.stringify(body)}`,
      'SUCCESS'
    );

    return createResponse(201, item);
  } catch (error) {
    if (error instanceof Error && error.message.includes('FORBIDDEN')) {
      return createResponse(403, { error: 'Access denied' });
    }
    console.error('Error in handleCreateRecord:', error);
    return createResponse(500, { error: 'Internal server error' });
  }
}

async function handleUpdateRecord(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  try {
    const authContext = extractAuthContext(event);
    requirePermission(authContext.role, 'UPDATE_RECORD');

    const tableIndex = event.pathParameters?.tableIndex || '0';
    const recordId = event.pathParameters?.id;

    if (!recordId) {
      return createResponse(400, { error: 'Record ID is required' });
    }

    const tableMap: Record<string, string> = {
      '0': 'SalesData',
      '1': 'ValidationRules',
      '2': 'AnomalyDetectionLog',
      '3': 'BillingItemDefinition',
      '4': 'CustomerBillingAggregation',
      '5': 'ServiceBillingAggregation',
      '6': 'SalesDataMetadata',
      '7': 'MonthlySummaryTemplate',
      '8': 'DataQualityValidationResult',
      '9': 'MissingDataNotificationLog',
      '10': 'User',
      '11': 'OperationHistory',
    };

    const targetTable = tableMap[tableIndex];
    if (!targetTable) {
      return createResponse(400, { error: 'Invalid table index' });
    }

    const body = JSON.parse(event.body || '{}');
    const now = new Date().toISOString();

    // Get existing record
    const getResult = await docClient.send(
      new QueryCommand({
        TableName: TABLE_NAME,
        KeyConditionExpression: 'pk = :pk AND begins_with(sk, :sk)',
        ExpressionAttributeValues: {
          ':pk': targetTable,
          ':sk': `${recordId}#`,
        },
        Limit: 1,
      })
    );

    if (!getResult.Items || getResult.Items.length === 0) {
      return createResponse(404, { error: 'Record not found' });
    }

    const existingRecord = getResult.Items[0];
    const updateExpressionParts: string[] = [];
    const expressionAttributeValues: Record<string, unknown> = {};
    const expressionAttributeNames: Record<string, string> = {};

    Object.entries(body).forEach(([key, value], index) => {
      const attrName = `#attr${index}`;
      const attrValue = `:val${index}`;
      updateExpressionParts.push(`${attrName} = ${attrValue}`);
      expressionAttributeNames[attrName] = key;
      expressionAttributeValues[attrValue] = value;
    });

    updateExpressionParts.push('#updatedAt = :updatedAt');
    updateExpressionParts.push('#updatedBy = :updatedBy');
    expressionAttributeNames['#updatedAt'] = 'updatedAt';
    expressionAttributeNames['#updatedBy'] = 'updatedBy';
    expressionAttributeValues[':updatedAt'] = now;
    expressionAttributeValues[':updatedBy'] = authContext.userId;

    const updateExpression = `SET ${updateExpressionParts.join(', ')}`;

    await docClient.send(
      new UpdateCommand({
        TableName: TABLE_NAME,
        Key: {
          pk: targetTable,
          sk: existingRecord.sk,
        },
        UpdateExpression: updateExpression,
        ExpressionAttributeNames,
        ExpressionAttributeValues: expressionAttributeValues,
      })
    );

    await createAuditLog(
      authContext.userId,
      'UPDATE',
      targetTable,
      recordId,
      `Updated record: ${JSON.stringify(body)}`,
      'SUCCESS'
    );

    return createResponse(200, { ...existingRecord, ...body, updatedAt: now, updatedBy: authContext.userId });
  } catch (error) {
    if (error instanceof Error && error.message.includes('FORBIDDEN')) {
      return createResponse(403, { error: 'Access denied' });
    }
    console.error('Error in handleUpdateRecord:', error);
    return createResponse(500, { error: 'Internal server error' });
  }
}

async function handleDeleteRecord(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  try {
    const authContext = extractAuthContext(event);
    requirePermission(authContext.role, 'DELETE_RECORD');

    const tableIndex = event.pathParameters?.tableIndex || '0';
    const recordId = event.pathParameters?.id;

    if (!recordId) {
      return createResponse(400, { error: 'Record ID is required' });
    }

    const tableMap: Record<string, string> = {
      '0': 'SalesData',
      '1': 'ValidationRules',
      '2': 'AnomalyDetectionLog',
      '3': 'BillingItemDefinition',
      '4': 'CustomerBillingAggregation',
      '5': 'ServiceBillingAggregation',
      '6': 'SalesDataMetadata',
      '7': 'MonthlySummaryTemplate',
      '8': 'DataQualityValidationResult',
      '9': 'MissingDataNotificationLog',
      '10': 'User',
      '11': 'OperationHistory',
    };

    const targetTable = tableMap[tableIndex];
    if (!targetTable) {
      return createResponse(400, { error: 'Invalid table index' });
    }

    // Get existing record
    const getResult = await docClient.send(
      new QueryCommand({
        TableName: TABLE_NAME,
        KeyConditionExpression: 'pk = :pk AND begins_with(sk, :sk)',
        ExpressionAttributeValues: {
          ':pk': targetTable,
          ':sk': `${recordId}#`,
        },
        Limit: 1,
      })
    );

    if (!getResult.Items || getResult.Items.length === 0) {
      return createResponse(404, { error: 'Record not found' });
    }

    const existingRecord = getResult.Items[0];

    await docClient.send(
      new DeleteCommand({
        TableName: TABLE_NAME,
        Key: {
          pk: targetTable,
          sk: existingRecord.sk,
        },
      })
    );

    await createAuditLog(
      authContext.userId,
      'DELETE',
      targetTable,
      recordId,
      'Deleted record',
      'SUCCESS'
    );

    return createResponse(200, { message: 'Record deleted successfully' });
  } catch (error) {
    if (error instanceof Error && error.message.includes('FORBIDDEN')) {
      return createResponse(403, { error: 'Access denied' });
    }
    console.error('Error in handleDeleteRecord:', error);
    return createResponse(500, { error: 'Internal server error' });
  }
}

async function handleGetRecord(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  try {
    const authContext = extractAuthContext(event);
    requirePermission(authContext.role, 'GET_RESOURCES');

    const tableIndex = event.pathParameters?.tableIndex || '0';
    const recordId = event.pathParameters?.id;

    if (!recordId) {
      return createResponse(400, { error: 'Record ID is required' });
    }

    const tableMap: Record<string, string> = {
      '0': 'SalesData',
      '1': 'ValidationRules',
      '2': 'AnomalyDetectionLog',
      '3': 'BillingItemDefinition',
      '4': 'CustomerBillingAggregation',
      '5': 'ServiceBillingAggregation',
      '6': 'SalesDataMetadata',
      '7': 'MonthlySummaryTemplate',
      '8': 'DataQualityValidationResult',
      '9': 'MissingDataNotificationLog',
      '10': 'User',
      '11': 'OperationHistory',
    };

    const targetTable = tableMap[tableIndex];
    if (!targetTable) {
      return createResponse(400, { error: 'Invalid table index' });
    }

    const result = await docClient.send(
      new QueryCommand({
        TableName: TABLE_NAME,
        KeyConditionExpression: 'pk = :pk AND begins_with(sk, :sk)',
        ExpressionAttributeValues: {
          ':pk': targetTable,
          ':sk': `${recordId}#`,
        },
        Limit: 1,
      })
    );

    if (!result.Items || result.Items.length === 0) {
      return createResponse(404, { error: 'Record not found' });
    }

    return createResponse(200, result.Items[0]);
  } catch (error) {
    if (error instanceof Error && error.message.includes('FORBIDDEN')) {
      return createResponse(403, { error: 'Access denied' });
    }
    console.error('Error in handleGetRecord:', error);
    return createResponse(500, { error: 'Internal server error' });
  }
}

export const handler = async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
  const path = event.path || '';
  const method = event.httpMethod || 'GET';

  console.log(`${method} ${path}`);

  try {
    // GET /resources
    if (method === 'GET' && path === '/resources') {
      return await handleGetResources(event);
    }

    // GET /api/{tableIndex}/{id}
    if (method === 'GET' && path.match(/^\/api\/\d+\/[a-f0-9-]+$/)) {
      return await handleGetRecord(event);
    }

    // POST /api/{tableIndex}/bulk
    if (method === 'POST' && path.match(/^\/api\/\d+\/bulk$/)) {
      return await handleBulkImport(event);
    }

    // POST /api/{tableIndex}
    if (method === 'POST' && path.match(/^\/api\/\d+$/)) {
      return await handleCreateRecord(event);
    }

    // PUT /api/{tableIndex}/{id}
    if (method === 'PUT' && path.match(/^\/api\/\d+\/[a-f0-9-]+$/)) {
      return await handleUpdateRecord(event);
    }

    // DELETE /api/{tableIndex}/{id}
    if (method === 'DELETE' && path.match(/^\/api\/\d+\/[a-f0-9-]+$/)) {
      return await handleDeleteRecord(event);
    }

    return createResponse(404, { error: 'Not found' });
  } catch (error) {
    console.error('Unhandled error:', error);
    return createResponse(500, { error: 'Internal server error' });
  }
};