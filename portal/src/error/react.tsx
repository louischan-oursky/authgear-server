import { createContext, useContext } from "react";
import { Values } from "@oursky/react-messageformat";
import { ValidationFailedErrorInfoCause } from "./validation";

export function getReactMessageFormatValues(
  cause: ValidationFailedErrorInfoCause
): Values {
  return cause.details;
}

interface FormContextShape {}

export const FormContext = createContext<FormContextShape | null>(null);

interface UseFormFieldProps {
  jsonPointer: string | RegExp;
}

interface UseFormFieldData {
  casues: ValidationFailedErrorInfoCause[];
}

export function useJSONPointer(props: UseFormFieldProps): UseFormFieldData {
  // TODO: implement this function
  const formContext = useContext(FormContext);
}

function ShowCauses() {}

function ShowOtherError() {}

function SomeScreen() {
  // otherError is undefined. unhandledCauses is array
  // otherError is non-null. unhandledCauses is undefined
  const { unhandledCauses, otherError, value } = useValidationError(error);

  return (
    <>
      <FormContext.Provider value={value}>
        <ShowUnhandledCauses causes={unhandledCauses} />
        <ShowOtherError error={otherError} />
        <JSONPointerTextField value={clientID} jsonPointer="asdasdasd" />
      </FormContext.Provider>
    </>
  );
}
