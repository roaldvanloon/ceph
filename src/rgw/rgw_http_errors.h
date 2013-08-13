#ifndef RGW_HTTP_ERRORS_H_
#define RGW_HTTP_ERRORS_H_

#include "rgw_common.h"

struct rgw_http_errors {
  int err_no;
  int http_ret;
  const char *s3_code;
};

const static struct rgw_http_errors RGW_HTTP_ERRORS[] = {
    { 0, 200, "" },
    { STATUS_CREATED, 201, "Created" },
    { STATUS_ACCEPTED, 202, "Accepted" },
    { STATUS_NO_CONTENT, 204, "NoContent" },
    { STATUS_PARTIAL_CONTENT, 206, "" },
    { ERR_PERMANENT_REDIRECT, 301, "PermanentRedirect" },
    { STATUS_REDIRECT, 303, "" },
    { ERR_NOT_MODIFIED, 304, "NotModified" },
    { EINVAL, 400, "InvalidArgument" },
    { ERR_INVALID_REQUEST, 400, "InvalidRequest" },
    { ERR_INVALID_DIGEST, 400, "InvalidDigest" },
    { ERR_BAD_DIGEST, 400, "BadDigest" },
    { ERR_INVALID_BUCKET_NAME, 400, "InvalidBucketName" },
    { ERR_INVALID_OBJECT_NAME, 400, "InvalidObjectName" },
    { ERR_UNRESOLVABLE_EMAIL, 400, "UnresolvableGrantByEmailAddress" },
    { ERR_INVALID_PART, 400, "InvalidPart" },
    { ERR_INVALID_PART_ORDER, 400, "InvalidPartOrder" },
    { ERR_REQUEST_TIMEOUT, 400, "RequestTimeout" },
    { ERR_TOO_LARGE, 400, "EntityTooLarge" },
    { ERR_TOO_SMALL, 400, "EntityTooSmall" },
    { ERR_TOO_MANY_BUCKETS, 400, "TooManyBuckets" },
    { ERR_LENGTH_REQUIRED, 411, "MissingContentLength" },
    { EACCES, 403, "AccessDenied" },
    { EPERM, 403, "AccessDenied" },
    { ERR_USER_SUSPENDED, 403, "UserSuspended" },
    { ERR_REQUEST_TIME_SKEWED, 403, "RequestTimeTooSkewed" },
    { ENOENT, 404, "NoSuchKey" },
    { ERR_NO_SUCH_BUCKET, 404, "NoSuchBucket" },
    { ERR_NO_SUCH_UPLOAD, 404, "NoSuchUpload" },
    { ERR_NOT_FOUND, 404, "Not Found"},
    { ERR_METHOD_NOT_ALLOWED, 405, "MethodNotAllowed" },
    { ETIMEDOUT, 408, "RequestTimeout" },
    { EEXIST, 409, "BucketAlreadyExists" },
    { ENOTEMPTY, 409, "BucketNotEmpty" },
    { ERR_PRECONDITION_FAILED, 412, "PreconditionFailed" },
    { ERANGE, 416, "InvalidRange" },
    { ERR_UNPROCESSABLE_ENTITY, 422, "UnprocessableEntity" },
    { ERR_LOCKED, 423, "Locked" },
    { ERR_INTERNAL_ERROR, 500, "InternalError" },
};

const static struct rgw_http_errors RGW_HTTP_SWIFT_ERRORS[] = {
    { EACCES, 401, "AccessDenied" },
    { EPERM, 401, "AccessDenied" },
    { ERR_USER_SUSPENDED, 401, "UserSuspended" },
    { ERR_INVALID_UTF8, 412, "Invalid UTF8" },
    { ERR_BAD_URL, 412, "Bad URL" },
};

const static struct rgw_http_errors RGW_HTTP_GS_ERRORS[] = {
    { ERR_PERMANENT_REDIRECT, 301, "PermanentRedirect" },
    { ERR_NOT_MODIFIED, 304, "NotModified" },
    { STATUS_REDIRECT, 307, "Redirect" },
    { ERR_TEMPORARY_REDIRECT, 307, "PermanentRedirect" },
    { ERR_RESUME_INCOMPLETE, 308, "Resume Incomplete" },
    { ERR_AMBIGUOUS_GRANT, 400, "AmbiguousGrantByEmailAddress" },
    { ERR_BAD_DIGEST, 400, "BadDigest" },
    { ERR_CREDENTIALS_NOT_SUPPORTED, 400, "CredentialsNotSupported" },
    { ERR_TOO_SMALL, 400, "EntityTooSmall" },
    { ERR_TOO_LARGE, 400, "EntityTooLarge" },
    { ERR_EXCESS_HEADERS, 400, "ExcessHeaderValues" },
    { ERR_TOKEN_EXPIRED, 400, "ExpiredToken" },
    { ERR_INCOMPLETE_BODY, 400, "IncompleteBody" },
    { ERR_POST_TOO_LARGE, 400, "IncorrectNumberOfFilesInPostRequest" },
    { ERR_INLINE_DATA_TOO_LARGE, 400, "InlineDataTooLarge" },

    { EINVAL, 400, "InvalidArgument" },
    { ERR_INVALID_BUCKET_NAME, 400, "InvalidBucketName" },
    { ERR_INVALID_DIGEST, 400, "InvalidDigest" },
    { ERR_INVALID_LOCATION, 400, "InvalidLocationConstraint" },
    { ERR_INVALID_POLICY, 400, "InvalidPolicyDocument" },
    { ERR_INVALID_STORAGECLASS, 400, "InvalidStorageClass" },
    { ERR_INVALID_TOKEN, 400, "InvalidToken" },
    { ERR_INVALID_URI, 400, "InvalidURI" },
    { ERR_INVALID_OBJECT_NAME, 400, "KeyTooLong" },

    { ERR_MALFORMED_ACL, 400, "MalformedACLError" },
    { ERR_MALFORMED_HEADER, 400, "MalformedHeaderValue" },
    { ERR_MALFORMED_POST, 400, "MalformedPOSTRequest" },
    { ERR_MALFORMED_XML, 400, "MalformedXML" },

    { ERR_REQUEST_TOO_BIG, 400, "MaxMessageLengthExceeded" },
    { ERR_PREDATA_TOO_BIG, 400, "MaxPostPreDataLengthExceededError" },
    { ERR_METADATA_TOO_BIG, 400, "MetadataTooLarge" },

    { ERR_MISSING_BODY, 400, "MissingRequestBodyError" },
    { ERR_MISSING_SECHEADER, 400, "MissingSecurityHeader" },

    { ERR_NO_LOGGING_FOR_KEY, 400, "NoLoggingStatusForKey" },
    { ERR_REQUEST_IS_NOT_MULTIPART, 400, "RequestIsNotMultiPartContent" },

    { ETIMEDOUT, 408, "RequestTimeout" },
    { ERR_TOKEN_REFRESH_REQUIRED, 400, "TokenRefreshRequired" },

    { ERR_TOO_MANY_BUCKETS, 400, "TooManyBuckets" },
    { ERR_UNEXPECTED_CONTENT, 400, "UnexpectedContent" },
    { ERR_UNRESOLVABLE_EMAIL, 400, "UnresolvableGrantByEmailAddress" },
    { ERR_UNSUPPORTED_ACL, 400, "UnsupportedAcl" },
    { ERR_UNSPECIFIED_KEY, 400, "UserKeyMustBeSpecified" },

    { EACCES, 401, "AccessDenied" },
    { EPERM, 401, "AccessDenied" },
    { ENOENT, 404, "NoSuchKey" },
    { ERR_NO_SUCH_BUCKET, 404, "NoSuchBucket" },

    { ERR_METHOD_NOT_ALLOWED, 405, "MethodNotAllowed" },

    { ERR_ALREADY_YOURS, 209, "BucketAlreadyOwnedByYou" },
    { EEXIST, 409, "BucketAlreadyExists" },
    { ENOTEMPTY, 409, "BucketNotEmpty" },
    { ERR_OP_ABORTED, 409, "OperationAborted" },

    { ERR_LENGTH_REQUIRED, 411, "MissingContentLength" },
    { ERR_PRECONDITION_FAILED, 412, "PreconditionFailed" },
    { ERANGE, 416, "InvalidRange" },
    { ERR_INTERNAL_ERROR, 500, "InternalError" },
    { ERR_NOT_IMPLEMENTED, 501, "NotImplemented" },
    { ERR_SLOWDOWN, 503, "SlowDown" },

};

#define ARRAY_LEN(arr) (sizeof(arr) / sizeof(arr[0]))

static inline const struct rgw_http_errors *search_err(int err_no, const struct rgw_http_errors *errs, int len)
{
  for (int i = 0; i < len; ++i, ++errs) {
    if (err_no == errs->err_no)
      return errs;
  }
  return NULL;
}


static inline int rgw_http_error_to_errno(int http_err)
{
  if (http_err >= 200 && http_err <= 299)
    return 0;
  switch (http_err) {
    case 400:
      return -EINVAL;
    case 401:
      return -EPERM;
    case 403:
        return -EACCES;
    case 404:
        return -ENOENT;
    default:
        return -EIO;
  }

  return 0; /* unreachable */
}


#endif
