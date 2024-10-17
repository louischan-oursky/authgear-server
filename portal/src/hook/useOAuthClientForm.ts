import deepEqual from "deep-equal";
import { produce, createDraft, Draft } from "immer";
import { getReducedClientConfig } from "../graphql/portal/EditOAuthClientForm";
import {
  OAuthClientConfig,
  OAuthClientSecret,
  PortalAPIAppConfig,
  PortalAPISecretConfig,
  PortalAPISecretConfigUpdateInstruction,
  SAMLBinding,
  SAMLNameIDAttributePointer,
  SAMLNameIDFormat,
  SAMLServiceProviderConfig,
} from "../types";
import { clearEmptyObject } from "../util/misc";
import { useAppSecretConfigForm } from "./useAppSecretConfigForm";
import { formatDuration, parseDuration } from "../util/duration";

interface FormStateSAMLServiceProviderConfig {
  clientID: string;
  isEnabled: boolean;
  nameIDFormat: SAMLNameIDFormat;
  nameIDAttributePointer?: SAMLNameIDAttributePointer;
  acsURLs: string[];
  desitination?: string;
  recipient?: string;
  audience?: string;
  assertionValidDurationSeconds?: number;
  isSLOEnabled?: boolean;
  sloCallbackURL?: string;
  sloCallbackBinding?: SAMLBinding;
  signatureVerificationEnabled?: boolean;
  certificates?: string[];
}

export interface FormState {
  publicOrigin: string;
  clients: OAuthClientConfig[];
  editedClient: OAuthClientConfig | null;
  removeClientByID?: string;
  clientSecretMap: Partial<Record<string, string>>;
  samlServiceProviders: FormStateSAMLServiceProviderConfig[];
}

function constructFormState(
  config: PortalAPIAppConfig,
  secrets: PortalAPISecretConfig
): FormState {
  const clientSecretMap: Partial<Record<string, string>> =
    secrets.oauthClientSecrets?.reduce<Record<string, string>>(
      (acc: Record<string, string>, currValue: OAuthClientSecret) => {
        if (currValue.keys?.length && currValue.keys.length >= 1) {
          acc[currValue.clientID] = currValue.keys[0].key;
        }
        return acc;
      },
      {}
    ) ?? {};

  const samlServiceProviders: FormStateSAMLServiceProviderConfig[] = [];
  for (const sp of config.saml?.service_providers ?? []) {
    samlServiceProviders.push({
      clientID: sp.client_id,
      isEnabled: true, // When there is a service provider exist, it means saml enabled for this client
      nameIDFormat: sp.nameid_format,
      nameIDAttributePointer: sp.nameid_attribute_pointer,
      acsURLs: sp.acs_urls,
      desitination: sp.destination,
      recipient: sp.recipient,
      audience: sp.audience,
      assertionValidDurationSeconds: sp.assertion_valid_duration
        ? parseDuration(sp.assertion_valid_duration)
        : undefined,
      isSLOEnabled: sp.slo_enabled,
      sloCallbackURL: sp.slo_callback_url,
      sloCallbackBinding: sp.slo_binding,
      signatureVerificationEnabled: sp.signature_verification_enabled,
      certificates:
        secrets.samlSpSigningSecrets
          ?.find((secret) => secret.clientID === sp.client_id)
          ?.certificates.map((cert) => cert.certificatePEM) ?? [],
    });
  }
  return {
    publicOrigin: config.http?.public_origin ?? "",
    clients: config.oauth?.clients ?? [],
    editedClient: null,
    removeClientByID: undefined,
    clientSecretMap,
    samlServiceProviders,
  };
}

function updateSAMLServiceProviders(
  config: Draft<PortalAPIAppConfig>,
  currentState: Draft<FormState>
) {
  const existingSPs = config.saml?.service_providers ?? [];
  const updatedSPs: SAMLServiceProviderConfig[] = [];
  for (const editedSP of currentState.samlServiceProviders) {
    if (!editedSP.isEnabled) {
      continue;
    }

    const updatedSP = existingSPs.find(
      (sp) => sp.client_id === editedSP.clientID
    ) ?? {
      client_id: editedSP.clientID,
      acs_urls: [],
      nameid_format: SAMLNameIDFormat.Unspecified,
    };

    updatedSP.nameid_format = editedSP.nameIDFormat;
    updatedSP.nameid_attribute_pointer = editedSP.nameIDAttributePointer;
    updatedSP.acs_urls = editedSP.acsURLs;
    updatedSP.destination = editedSP.desitination;
    updatedSP.recipient = editedSP.recipient;
    updatedSP.audience = editedSP.audience;
    updatedSP.assertion_valid_duration = editedSP.assertionValidDurationSeconds
      ? formatDuration(editedSP.assertionValidDurationSeconds, "s")
      : undefined;
    updatedSP.slo_enabled = editedSP.isSLOEnabled;
    updatedSP.slo_callback_url = editedSP.sloCallbackURL;
    updatedSP.slo_binding = editedSP.sloCallbackBinding;
    updatedSP.signature_verification_enabled =
      editedSP.signatureVerificationEnabled;

    updatedSPs.push(updatedSP);
  }

  config.saml ??= {};
  config.saml.service_providers = updatedSPs;
}

function constructConfig(
  config: PortalAPIAppConfig,
  secrets: PortalAPISecretConfig,
  _initialState: FormState,
  currentState: FormState,
  _effectiveConfig: PortalAPIAppConfig
): [PortalAPIAppConfig, PortalAPISecretConfig] {
  const [newConfig, _] = produce(
    [config, currentState],
    ([config, currentState]) => {
      config.oauth ??= {};
      config.oauth.clients = currentState.clients;

      if (currentState.removeClientByID) {
        config.oauth.clients = config.oauth.clients.filter(
          (c) => c.client_id !== currentState.removeClientByID
        );
        clearEmptyObject(config);
        return;
      }

      const client = currentState.editedClient;
      if (client) {
        const index = config.oauth.clients.findIndex(
          (c) => c.client_id === client.client_id
        );
        if (
          index !== -1 &&
          !deepEqual(
            getReducedClientConfig(client),
            getReducedClientConfig(config.oauth.clients[index]),
            { strict: true }
          )
        ) {
          config.oauth.clients[index] = createDraft(client);
        }
      }
      clearEmptyObject(config);

      updateSAMLServiceProviders(config, currentState);
    }
  );
  return [newConfig, secrets];
}

function constructSecretUpdateInstruction(
  _config: PortalAPIAppConfig,
  _secrets: PortalAPISecretConfig,
  currentState: FormState
): PortalAPISecretConfigUpdateInstruction | undefined {
  if (currentState.removeClientByID) {
    return {
      oauthClientSecrets: {
        action: "cleanup",
        cleanupData: {
          keepClientIDs: currentState.clients
            .filter((c) => c.client_id !== currentState.removeClientByID)
            .map((c) => c.client_id),
        },
      },
    };
  }

  return undefined;
}

export function useOAuthClientForm(
  appID: string,
  secretVisitToken: string | null
): ReturnType<typeof useAppSecretConfigForm<FormState>> {
  return useAppSecretConfigForm({
    appID,
    secretVisitToken,
    constructFormState,
    constructConfig,
    constructSecretUpdateInstruction,
  });
}
