import { Values } from "@oursky/react-messageformat";
import { ValidationFailedErrorInfoCause } from "./validation";

export function getReactMessageFormatValues(
  cause: ValidationFailedErrorInfoCause
): Values {
  return cause.details;
}
