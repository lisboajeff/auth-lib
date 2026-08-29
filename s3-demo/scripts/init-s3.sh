#!/bin/bash
echo "=== Initializing LocalStack S3 Bucket 'auth-bucket' ==="
awslocal s3 mb s3://auth-bucket || true
echo "=== LocalStack S3 Bucket Ready! ==="
