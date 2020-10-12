import { ApolloError } from "@apollo/client";
import { Values } from "@oursky/react-messageformat";
import { GraphQLError } from "graphql";

// throw this if unrecognized error encountered
class UnrecognizedError extends Error {}

// expected data shape of error extension from backend
interface RequiredErrorCauseDetails {
  actual: string[];
  expected: string[];
  missing: string[];
}

interface RequiredErrorCause {
  details: RequiredErrorCauseDetails;
  location: string;
  kind: "required";
}

interface GeneralErrorCauseDetails {
  msg: string;
}

interface GeneralErrorCause {
  details: GeneralErrorCauseDetails;
  location: string;
  kind: "general";
}

interface FormatErrorCauseDetails {
  format: string;
}

interface FormatErrorCause {
  details: FormatErrorCauseDetails;
  location: string;
  kind: "format";
}

interface MinItemsErrorCauseDetails {
  actual: number;
  expected: number;
}

interface MinItemsErrorCause {
  details: MinItemsErrorCauseDetails;
  location: string;
  kind: "minItems";
}

interface MinimumErrorCauseDetails {
  actual: number;
  minimum: number;
}

interface MinimumErrorCause {
  details: MinimumErrorCauseDetails;
  location: string;
  kind: "minimum";
}

interface MaximumErrorCauseDetails {
  actual: number;
  maximum: number;
}

interface MaximumErrorCause {
  details: MaximumErrorCauseDetails;
  location: string;
  kind: "maximum";
}

// union type of cause details, depend on kind
type ValidationErrorCause =
  | RequiredErrorCause
  | GeneralErrorCause
  | FormatErrorCause
  | MinItemsErrorCause
  | MinimumErrorCause
  | MaximumErrorCause;

interface ValidationErrorInfo {
  causes: ValidationErrorCause[];
}

interface APIValidationError {
  errorName: string;
  info: ValidationErrorInfo;
  reason: "ValidationFailed";
}

type InvariantViolationErrorKind = "RemoveLastIdentity";

interface InvariantViolationErrorCause {
  kind: InvariantViolationErrorKind;
}

interface InvariantViolationErrorInfo {
  cause: InvariantViolationErrorCause;
}

interface APIInvariantViolationError {
  errorName: string;
  info: InvariantViolationErrorInfo;
  reason: "InvariantViolated";
}

interface APIDuplicatedIdentityError {
  errorName: string;
  reason: "DuplicatedIdentity";
}

interface APIInvalidError {
  errorName: string;
  reason: "Invalid";
}

interface PasswordPolicyViolatedErrorCause {
  Name: string;
  Info: unknown;
}

interface PasswordPolicyViolatedErrorInfo {
  causes: PasswordPolicyViolatedErrorCause[];
}

interface APIPasswordPolicyViolatedError {
  errorName: string;
  info: PasswordPolicyViolatedErrorInfo;
  reason: "PasswordPolicyViolated";
}

// union type of api errors, depend on reason
type APIError =
  | APIValidationError
  | APIInvariantViolationError
  | APIInvalidError
  | APIDuplicatedIdentityError
  | APIPasswordPolicyViolatedError;

function isAPIError(value?: { [key: string]: any }): value is APIError {
  if (value == null) {
    return false;
  }
  return "errorName" in value && "reason" in value;
}

interface FieldErrorHandlingRule {
  errorMessageID: string;
  jsonPointer: RegExp | string;
  fieldName: string;
  fieldNameMessageID?: string;
  violationType: ValidationErrorCause["kind"]; // violation type in JSON schema
}

interface GenericErrorHandlingRule {
  errorMessageID: string;
  reason: APIError["reason"];
  kind?: string;
  cause?: string;
}

export function constructErrorMessageFromGenericGraphQLError(
  renderToString: (messageID: string, values?: Values) => string,
  error: GraphQLError,
  rules: GenericErrorHandlingRule[]
): string | null {
  if (!isAPIError(error.extensions)) {
    return null;
  }

  const { extensions } = error;
  for (const rule of rules) {
    if (extensions.reason !== rule.reason) {
      continue;
    }
    // some error reason need special handling
    // depends on error info
    if (extensions.reason === "InvariantViolated") {
      const cause = extensions.info.cause;
      if (cause.kind === rule.cause) {
        return renderToString(rule.errorMessageID);
      }
      continue;
    }
    if (extensions.reason === "PasswordPolicyViolated") {
      const causes = extensions.info.causes;
      const causeNames = causes.map((cause) => cause.Name);
      if (rule.cause != null && causeNames.includes(rule.cause)) {
        return renderToString(rule.errorMessageID);
      }
      continue;
    }
    // for other error reason, only need to match reason
    return rule.errorMessageID;
  }

  // no matching rules
  return null;
}

// Final error boundary, return fallback error message if error unrecognized
// NOTE: This can be constructed by custom hook?
// so don't need to pass renderToString, and pass rules to hook as it is static
export function handleGenericError(
  error: unknown,
  rules: GenericErrorHandlingRule[],
  renderToString: (messageID: string, values?: Values) => string,
  fallbackErrorMessageID: string = "error.unknownError"
): string | undefined {
  if (error == null) {
    return undefined;
  }

  const fallbackErrorMessage = renderToString(fallbackErrorMessageID);
  if (!(error instanceof ApolloError)) {
    console.warn("[Handle generic error]: Unhandled error\n", error);
    return fallbackErrorMessage;
  }

  const errorMessageList: string[] = [];
  let containUnrecognizedError = false;
  for (const graphQLError of error.graphQLErrors) {
    const errorMessage = constructErrorMessageFromGenericGraphQLError(
      renderToString,
      graphQLError,
      rules
    );
    if (errorMessage != null) {
      errorMessageList.push(errorMessage);
    } else {
      console.warn(
        "[Handle generic error]: Contains unrecognized graphQL error \n",
        graphQLError
      );
      containUnrecognizedError = true;
    }
  }
  if (containUnrecognizedError) {
    errorMessageList.push(fallbackErrorMessage);
  }

  return errorMessageList.join("\n");
}

function isLocationMatchWithJSONPointer(
  jsonPointer: RegExp | string,
  location: string
) {
  if (typeof jsonPointer === "string") {
    return location.startsWith(jsonPointer);
  }
  return jsonPointer.test(location);
}

// pass violation specific data by values in renderToString
function getMessageValuesFromValidationErrorCause(
  cause: ValidationErrorCause
): Values {
  switch (cause.kind) {
    // special handle required violation, not used for now
    case "required":
      return {
        missingFields: cause.details.missing.join(", "),
      };
    case "general":
      return {};
    case "format":
      return {
        format: cause.details.format,
      };
    case "minItems":
      return {
        minItems: cause.details.expected,
      };
    case "minimum":
      return {
        minimum: cause.details.minimum,
      };
    case "maximum":
      return {
        maximum: cause.details.maximum,
      };
    default:
      throw new UnrecognizedError();
  }
}

function addErrorMessageToErrorMap<K extends string>(
  errorMessageList: Partial<Record<K, string[]>>,
  newErrorMessage: string,
  fieldName: K
) {
  errorMessageList[fieldName] = errorMessageList[fieldName] ?? [];
  errorMessageList[fieldName]?.push(newErrorMessage);
}

function constructErrorMessageFromValidationErrorCause(
  renderToString: (messageID: string, values?: Values) => string,
  cause: ValidationErrorCause,
  rules: FieldErrorHandlingRule[],
  errorMessageList: Record<string, string[]>
): boolean {
  for (const rule of rules) {
    // check violation type
    if (rule.violationType === cause.kind) {
      // check JSON pointer
      if (isLocationMatchWithJSONPointer(rule.jsonPointer, cause.location)) {
        // special handle required violation, needs to match missing field
        if (cause.kind === "required") {
          if (cause.details.missing.includes(rule.fieldName)) {
            // fallback to raw field name if field name message ID not exist
            let localizedFieldName = rule.fieldName;
            if (rule.fieldNameMessageID != null) {
              localizedFieldName = renderToString(rule.fieldNameMessageID);
            } else {
              console.warn(
                "[Construct validation error message]: Expect fieldNameMessageID in rules for `required` violation error"
              );
            }
            addErrorMessageToErrorMap(
              errorMessageList,
              renderToString(rule.errorMessageID, {
                fieldName: localizedFieldName,
              }),
              rule.fieldName
            );
            return true;
          }
          continue;
        }
        // other than required violation, matching json pointer => matching field
        // unrecognized error kind (violation type) => throw error in get message value
        try {
          const errorMessageValues = getMessageValuesFromValidationErrorCause(
            cause
          );
          addErrorMessageToErrorMap(
            errorMessageList,
            renderToString(rule.errorMessageID, errorMessageValues),
            rule.fieldName
          );
          return true;
        } catch {
          console.warn(
            "[Unhandled validation error cause]: Unrecognized cause kind\n",
            cause
          );
          return false;
        }
      }
    }
  }
  // no matching rules
  console.warn(
    "[Unhandled validation error cause]: No matching rule provided\n",
    cause
  );
  return false;
}

// handle error which is passed to form, throw if error cannot be
// handled within form (not field specific error)
export function parseFormError(
  error: unknown
): {
  validationErrorCauses: ValidationErrorCause[];
  containsUnhandledViolation: boolean;
} {
  let containsUnhandledViolation = false;
  const validationErrorCauses: ValidationErrorCause[] = [];
  if (error == null) {
    return { validationErrorCauses: [], containsUnhandledViolation: false };
  }
  if (!(error instanceof ApolloError)) {
    return { validationErrorCauses, containsUnhandledViolation: true };
  }

  for (const graphQLError of error.graphQLErrors) {
    if (!isAPIError(graphQLError.extensions)) {
      containsUnhandledViolation = true;
      continue;
    }
    const { extensions } = graphQLError;
    if (extensions.reason === "ValidationFailed") {
      const { causes } = extensions.info;
      validationErrorCauses.push(...causes);
      continue;
    }
    containsUnhandledViolation = true;
  }

  // unhandled error
  return { validationErrorCauses, containsUnhandledViolation };
}

// NOTE: This can be constructed by custom hook?
// so don't need to pass renderToString, and pass rules to hook as it is static
export function handleFormError(
  error: unknown,
  rules: FieldErrorHandlingRule[],
  errorMessageList: Record<string, string[]>,
  renderToString: (messageID: string, values?: Values) => string
): void {
  const { validationErrorCauses, containsUnhandledViolation } = parseFormError(
    error
  );
  let containsUnhandledValidationErrorCause = false;
  for (const validationErrorCause of validationErrorCauses) {
    const handled = constructErrorMessageFromValidationErrorCause(
      renderToString,
      validationErrorCause,
      rules,
      errorMessageList
    );
    containsUnhandledValidationErrorCause =
      containsUnhandledValidationErrorCause || !handled;
  }

  if (containsUnhandledViolation || containsUnhandledValidationErrorCause) {
    // Cannot handle error, throw to next layer (generic error)
    throw error;
  }
}
