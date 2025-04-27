---
title: AWS S3 IAM Roles and External IDs
sidebar_position: 2
---

# AWS S3 IAM Roles and External IDs

This guide explains how to use IAM role assumption and External IDs with Quickwit's S3 storage for enhanced security and performance.

## Overview

Quickwit supports two advanced AWS S3 security features:

1. **IAM Role Assumption**: Allows Quickwit to temporarily assume IAM roles with specific permissions
2. **External IDs**: Provides an additional layer of security for cross-account role assumption

These features enable secure cross-account access to S3 buckets and apply the principle of least privilege to your storage access patterns.

## Configuring Storage Credentials

You can configure IAM roles and External IDs at the index level using the `storage_credentials` section in your index configuration:

```yaml
version: 0.8
index_id: my-index
index_uri: s3://my-bucket/my-index

# Storage credentials configuration
storage_credentials:
  s3:
    role_arn: arn:aws:iam::123456789012:role/QuickwitIndexRole
    external_id: my-external-id-token  # Optional
```

### Parameters

| Parameter | Description | Required |
|-----------|-------------|----------|
| `storage_credentials.s3.role_arn` | ARN of the IAM role to assume | Yes, for role assumption |
| `storage_credentials.s3.external_id` | External ID token for enhanced security | No, only with role_arn |

## Use Cases

### Cross-Account Access

Securely access S3 buckets in different AWS accounts:

```yaml
index_id: logs-index
index_uri: s3://logs-bucket/logs-index
storage_credentials:
  s3:
    role_arn: arn:aws:iam::987654321098:role/LogsAccessRole
    external_id: partner-access-token
```

### Different Permissions per Index

Use different IAM roles for different indexes to apply least privilege:

```yaml
# First index with read/write permissions
index_id: inventory
index_uri: s3://app-data/inventory
storage_credentials:
  s3:
    role_arn: arn:aws:iam::123456789012:role/InventoryWriteRole

# Second index with read-only permissions
index_id: catalog
index_uri: s3://app-data/catalog
storage_credentials:
  s3:
    role_arn: arn:aws:iam::123456789012:role/CatalogReadOnlyRole
```

## IAM Role Configuration

When setting up your IAM roles in AWS, ensure:

1. The role has the necessary S3 permissions for the bucket
2. The role's trust policy allows Quickwit to assume it

Example trust policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:role/QuickwitServiceRole"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "my-external-id-token"
        }
      }
    }
  ]
}
```

## External ID Security

External IDs add an extra layer of security to prevent the "confused deputy" problem. When a third party (like Quickwit) needs to access resources in multiple AWS accounts, the External ID ensures that it's acting on behalf of the correct entity.

Best practices for External IDs:
- Use complex, random strings
- Rotate External IDs periodically
- Never share External IDs outside your organization

## Performance Optimization with Client Caching

Quickwit automatically caches S3 clients to improve performance when using role assumption. This reduces the number of STS (Security Token Service) calls needed to assume roles, which:

1. Improves performance by reducing role assumption overhead
2. Reduces the risk of hitting AWS API rate limits
3. Minimizes latency for S3 operations

The cache is managed per role ARN, so different indexes using the same role will share the same S3 client.

## Debugging

When troubleshooting S3 role assumption issues, enable debug logging:

```bash
RUST_LOG=quickwit_storage=debug quickwit [command]
```

Look for logs containing:
- "Assuming IAM role for S3 access"
- "Using cached S3 client for role ARN"
- "Creating new S3 client for role ARN"

## Limitations

- Role session tokens have a default expiration of 1 hour
- External IDs must be used with role ARNs (they cannot be used alone)
- Role ARNs can only be used with S3 URIs