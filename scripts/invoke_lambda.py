
from boto3 import Session
import json
import base64
import gzip
import argparse

LAMBDA_NAME = "quickwit-searcher"

def invoke_lambda(lambda_name, index_id: str, query: str):
    body = json.dumps({
        "query": query,
        "max_hits": 2500,
    })

    session = Session()
    client = session.client("lambda")
    resp = client.invoke(
        FunctionName=lambda_name,
        InvocationType="RequestResponse",
        LogType="Tail",
        Payload=json.dumps(
            {
                "resource": f"/api/v1/{index_id}/search",
                "path": f"/api/v1/{index_id}/search",
                "httpMethod": "POST",
                "headers": {
                    "Content-Type": "application/json",
                },
                "requestContext": {
                    "httpMethod": "POST",
                },
                "body": body,
                "isBase64Encoded": False,
            }
        ),
    )

    log_result = base64.b64decode(resp["LogResult"])
    log_out = str(log_result, 'utf-8')
    print(log_out)
    print("\n\n\n")

    payload_str = resp["Payload"].read().decode('utf-8')
    quickwit_resp = json.loads(payload_str)
    if "errorType" in quickwit_resp:
        print("Lambda Response Payload:")
        print(payload_str)
        return
    
    if "statusCode" in quickwit_resp:
        if quickwit_resp["statusCode"] // 100 != 2:
            print("Lambda Response Payload:")
            print(payload_str)
            return

    qw_body = quickwit_resp["body"]
    decoded_body = base64.b64decode(qw_body)
    decompressed_body = gzip.decompress(decoded_body)
    json_body = json.loads(decompressed_body)
    print("\nDecompressed QuickWit Response:")
    print(json.dumps(json_body, indent=2))


def main():
    parser = argparse.ArgumentParser(description='Invoke QuickWit Lambda function')
    parser.add_argument('index_id')
    parser.add_argument('query')
    args = parser.parse_args()
    
    invoke_lambda(LAMBDA_NAME, args.index_id, args.query)


if __name__ == "__main__":
    main()
