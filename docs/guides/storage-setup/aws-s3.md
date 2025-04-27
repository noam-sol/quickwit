---
title: AWS S3
sidebar_position: 1
---

In this guide, you will learn how to configure a Quickwit [storage](../../configuration/storage-config) for Amazon S3.

## Set your AWS credentials

A simple way to do it is to declare the environment variables `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`. For more details, read our guide on [AWS setup](../aws-setup).

For advanced authentication scenarios like cross-account access or applying the principle of least privilege, you can use IAM role assumption instead. See [AWS S3 IAM Roles and External IDs](./aws-s3-iam-roles.md) for details.

## Set the Metastore URI and default index URI

Here is an example of how to set up your [node config file](../../configuration/node-config) with S3:

```yaml
metastore_uri: s3://{my-bucket}/indexes
default_index_uri: s3://{my-bucket}/indexes
```

## Set the Index URI

Here is an example of how to set up your index URI in the [index config file](../../configuration/index-config):
```yaml
index_uri: s3://{my-bucket}/indexes/{my-index-id}
```

## Using IAM Roles with S3 (Optional)

If you need to access S3 buckets with specific IAM roles or in different AWS accounts, you can configure index-specific credentials:

```yaml
index_uri: s3://{my-bucket}/indexes/{my-index-id}

# Optional: Configure S3 credentials for this index
storage_credentials:
  s3:
    role_arn: arn:aws:iam::123456789012:role/S3AccessRole
    external_id: my-external-id-token  # Optional
```

This approach is particularly useful for:
- Accessing buckets in different AWS accounts
- Applying different permission levels to different indexes
- Implementing the principle of least privilege

See [AWS S3 IAM Roles and External IDs](./aws-s3-iam-roles.md) for a complete guide on using IAM roles with Quickwit.
