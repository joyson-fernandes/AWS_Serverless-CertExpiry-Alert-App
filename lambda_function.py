import json
import boto3
from botocore.exceptions import ClientError
from decimal import Decimal

# Initialize the DynamoDB client
dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
dynamodb_table = dynamodb.Table('certifications')

status_check_path = '/status'
certificate_path = '/certificate'
certificates_path = '/certificates'

def lambda_handler(event, context):
    print('Request event: ', event)
    response = None

    try:
        http_method = event.get('httpMethod')
        path = event.get('path')

        if http_method == 'GET' and path == status_check_path:
            response = build_response(200, 'Service is operational')
        elif http_method == 'GET' and path == certificate_path:
            certname = event['queryStringParameters']['certname']
            response = get_certificate(certname)
        elif http_method == 'GET' and path == certificates_path:
            response = get_certificates()
        elif http_method == 'POST' and path == certificate_path:
            response = save_certificate(json.loads(event['body']))
        elif http_method == 'PATCH' and path == certificate_path:
            body = json.loads(event['body'])
            response = modify_certificate(body['certname'], body['updateKey'], body['updateValue'])
        elif http_method == 'DELETE' and path == certificate_path:
            body = json.loads(event['body'])
            response = delete_certificate(body['certname'])
        else:
            response = build_response(404, '404 Not Found')

    except Exception as e:
        print('Error:', e)
        response = build_response(400, 'Error processing request')

    return response

def get_certificate(certname):
    try:
        response = dynamodb_table.get_item(Key={'certname': certname})
        return build_response(200, response.get('Item'))
    except ClientError as e:
        print('Error:', e)
        return build_response(400, e.response['Error']['Message'])

def get_certificates():
    try:
        scan_params = {
            'TableName': dynamodb_table.name
        }
        return build_response(200, scan_dynamo_records(scan_params, []))
    except ClientError as e:
        print('Error:', e)
        return build_response(400, e.response['Error']['Message'])

def scan_dynamo_records(scan_params, item_array):
    response = dynamodb_table.scan(**scan_params)
    item_array.extend(response.get('Items', []))

    if 'LastEvaluatedKey' in response:
        scan_params['ExclusiveStartKey'] = response['LastEvaluatedKey']
        return scan_dynamo_records(scan_params, item_array)
    else:
        return {'certificates': item_array}

def save_certificate(request_body):
    try:
        # Validate required fields
        required_fields = ['certname', 'issueDate', 'expireDate']
        for field in required_fields:
            if field not in request_body or request_body[field] == "":
                return build_response(400, {'Message': f'Missing or invalid required field: {field}'})

        # Save certificate data to DynamoDB
        dynamodb_table.put_item(Item=request_body)

        body = {
            'Operation': 'SAVE',
            'Message': 'SUCCESS',
            'Item': request_body
        }
        return build_response(200, body)
    except ClientError as e:
        print('Error:', e)
        return build_response(400, {'Message': e.response['Error']['Message']})

def modify_certificate(certname, update_key, update_value):
    try:
        response = dynamodb_table.update_item(
            Key={'certname': certname},
            UpdateExpression=f'SET {update_key} = :value',
            ExpressionAttributeValues={':value': update_value},
            ReturnValues='UPDATED_NEW'
        )
        body = {
            'Operation': 'UPDATE',
            'Message': 'SUCCESS',
            'UpdatedAttributes': response['Attributes']
        }
        return build_response(200, body)
    except ClientError as e:
        print('Error:', e)
        return build_response(400, {'Message': e.response['Error']['Message']})


def delete_certificate(certname):
    try:
        response = dynamodb_table.delete_item(
            Key={'certname': certname},
            ReturnValues='ALL_OLD'  # This returns the attributes of the item before deletion
        )
        body = {
            'Operation': 'DELETE',
            'Message': 'SUCCESS',
            'Item': response.get('Attributes', None)  # Get the deleted item's attributes
        }
        return build_response(200, body)
    except ClientError as e:
        print('Error:', e)
        return build_response(400, {'Message': e.response['Error']['Message']})


class DecimalEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Decimal):
            # Check if it's an int or a float
            if obj % 1 == 0:
                return int(obj)
            else:
                return float(obj)
        # Let the base class default method raise the TypeError
        return super(DecimalEncoder, self).default(obj)

def build_response(status_code, body):
    return {
        'statusCode': status_code,
        'headers': {
            'Content-Type': 'application/json'
        },
        'body': json.dumps(body, cls=DecimalEncoder)
    }