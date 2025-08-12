import argparse
import base64
import json

from boto3 import Session
from construct import Byte, Enum, Struct

LAMBDA_NAME = "quickwit-searcher"

RootSearcherLambdaResponseFooter = Struct(
    "content_type" / Enum(Byte, EMBED=0, S3_LINK=1),
    "version" / Byte,
)


def handle_qw_response(qw_body: str) -> None:
    data = qw_body.encode()

    footer_size = RootSearcherLambdaResponseFooter.sizeof()
    if len(data) <= footer_size:
        raise ValueError("QuickWit body too short")

    payload = data[:-footer_size]
    footer = RootSearcherLambdaResponseFooter.parse(data[-footer_size:])

    if footer.content_type == "EMBED":
        # Prettify json response
        print(json.dumps(json.loads(payload.decode()), indent=2))
    elif footer.content_type == "S3_LINK":
        print("S3 link (TODO: fetch via boto3):", payload.decode().strip())
    else:
        raise ValueError(f"Unknown content_type: {footer.content_type}")


def invoke_lambda(lambda_name: str, index_id: str, query: str, size: int) -> None:
    body = json.dumps(
        {
            "query": query,
            "max_hits": size,
        }
    )

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
    log_out = str(log_result, "utf-8")
    print(log_out)
    print("\n\n\n")

    payload_str = resp["Payload"].read().decode("utf-8")
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

    print("\nQuickWit Response:")
    handle_qw_response(qw_body)


def main():
    parser = argparse.ArgumentParser(description="Invoke QuickWit Lambda function")
    parser.add_argument("--index", required=True)
    parser.add_argument("--query", required=True)
    parser.add_argument("--size", type=int, default=1, help="number of hits to return, 1 by default")
    args = parser.parse_args()

    invoke_lambda(LAMBDA_NAME, args.index, args.query, args.size)


if __name__ == "__main__":
    main()
