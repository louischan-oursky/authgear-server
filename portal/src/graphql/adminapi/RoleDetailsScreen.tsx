import React, {
  useCallback,
  useContext,
  useMemo,
  useState,
  useRef,
} from "react";
import {
  RoleAndGroupsFormFooter,
  RoleAndGroupsLayout,
  RoleAndGroupsVeriticalFormLayout,
} from "../../RoleAndGroupsLayout";
import { useFormContainerBaseContext } from "../../FormContainerBase";
import { BreadcrumbItem } from "../../NavBreadcrumb";
import {
  Context as MessageContext,
  FormattedMessage,
} from "@oursky/react-messageformat";
import { useNavigate, useParams } from "react-router-dom";
import ShowError from "../../ShowError";
import ShowLoading from "../../ShowLoading";
import { useRoleQuery } from "./query/roleQuery";
import { RoleQueryNodeFragment } from "./query/roleQuery.generated";
import { validateRole } from "../../model/role";
import { APIError } from "../../error/error";
import { makeLocalValidationError } from "../../error/validation";
import { SimpleFormModel, useSimpleForm } from "../../hook/useSimpleForm";
import WidgetDescription from "../../WidgetDescription";
import FormTextField from "../../FormTextField";
import { RoleAndGroupsFormContainer } from "./RoleAndGroupsFormContainer";
import PrimaryButton from "../../PrimaryButton";
import DefaultButton from "../../DefaultButton";
import { useSystemConfig } from "../../context/SystemConfigContext";
import { useUpdateRoleMutation } from "./mutations/updateRoleMutation";
import { usePivotNavigation } from "../../hook/usePivot";
import { Pivot, PivotItem } from "@fluentui/react";
import DeleteRoleDialog, { DeleteRoleDialogData } from "./DeleteRoleDialog";
import { GroupsEmptyView } from "../../components/roles-and-groups/GroupsEmptyView";
import { useQuery } from "@apollo/client";
import {
  GroupsListQueryDocument,
  GroupsListQueryQuery,
  GroupsListQueryQueryVariables,
} from "./query/groupsListQuery.generated";
import {
  GroupsList,
  GroupsListColumnKey,
  GroupsListItem,
} from "../../components/roles-and-groups/GroupsList";

interface FormState {
  roleKey: string;
  roleName: string;
  roleDescription: string;
}

const SETTINGS_KEY = "settings";
const GROUPS_KEY = "groups";

function RoleDetailsScreenSettingsForm({
  onClickDeleteRole,
}: {
  onClickDeleteRole: () => void;
}) {
  const { themes } = useSystemConfig();
  const { renderToString } = useContext(MessageContext);

  const {
    form: { state: formState, setState: setFormState },
    isUpdating,
    canSave,
  } = useFormContainerBaseContext<SimpleFormModel<FormState, string | null>>();

  const onFormStateChangeCallbacks = useMemo(() => {
    const createCallback = (key: keyof FormState) => {
      return (e: React.FormEvent<HTMLInputElement | HTMLTextAreaElement>) => {
        const newValue = e.currentTarget.value;
        setFormState((prev) => {
          return { ...prev, [key]: newValue };
        });
      };
    };
    return {
      roleKey: createCallback("roleKey"),
      roleName: createCallback("roleName"),
      roleDescription: createCallback("roleDescription"),
    };
  }, [setFormState]);

  return (
    <div>
      <RoleAndGroupsVeriticalFormLayout>
        <div>
          <FormTextField
            required={true}
            fieldName="name"
            parentJSONPointer=""
            type="text"
            label={renderToString("AddRolesScreen.roleName.title")}
            value={formState.roleName}
            onChange={onFormStateChangeCallbacks.roleName}
          />
          <WidgetDescription className="mt-2">
            <FormattedMessage id="AddRolesScreen.roleName.description" />
          </WidgetDescription>
        </div>
        <div>
          <FormTextField
            required={true}
            fieldName="key"
            parentJSONPointer=""
            type="text"
            label={renderToString("AddRolesScreen.roleKey.title")}
            value={formState.roleKey}
            onChange={onFormStateChangeCallbacks.roleKey}
          />
          <WidgetDescription className="mt-2">
            <FormattedMessage id="AddRolesScreen.roleKey.description" />
          </WidgetDescription>
        </div>
        <FormTextField
          multiline={true}
          resizable={false}
          autoAdjustHeight={true}
          rows={3}
          fieldName="description"
          parentJSONPointer=""
          type="text"
          label={renderToString("AddRolesScreen.roleDescription.title")}
          value={formState.roleDescription}
          onChange={onFormStateChangeCallbacks.roleDescription}
        />
      </RoleAndGroupsVeriticalFormLayout>

      <RoleAndGroupsFormFooter className="mt-12">
        <PrimaryButton
          disabled={!canSave || isUpdating}
          type="submit"
          text={<FormattedMessage id="save" />}
        />
        <DefaultButton
          disabled={isUpdating}
          theme={themes.destructive}
          type="button"
          onClick={onClickDeleteRole}
          text={<FormattedMessage id="RoleDetailsScreen.button.deleteRole" />}
        />
      </RoleAndGroupsFormFooter>
    </div>
  );
}

function RoleDetailsScreenSettingsFormContainer({
  role,
}: {
  role: RoleQueryNodeFragment;
}) {
  const { appID } = useParams() as { appID: string };
  const { updateRole } = useUpdateRoleMutation();
  const navigate = useNavigate();

  const isDeletedRef = useRef(false);

  const validate = useCallback((rawState: FormState): APIError | null => {
    const [_, errors] = validateRole({
      key: rawState.roleKey,
      name: rawState.roleName,
      description: rawState.roleDescription,
    });
    if (errors.length > 0) {
      return makeLocalValidationError(errors);
    }
    return null;
  }, []);

  const submit = useCallback(
    async (rawState: FormState) => {
      const [sanitizedRole, errors] = validateRole({
        key: rawState.roleKey,
        name: rawState.roleName,
        description: rawState.roleDescription,
      });
      if (errors.length > 0) {
        throw new Error("unexpected validation errors");
      }
      await updateRole({
        id: role.id,
        key: sanitizedRole.key,
        name: sanitizedRole.name,
        description: sanitizedRole.description,
      });
    },
    [role.id, updateRole]
  );

  const defaultState = useMemo((): FormState => {
    return {
      roleKey: role.key,
      roleName: role.name ?? "",
      roleDescription: role.description ?? "",
    };
  }, [role]);

  const form = useSimpleForm({
    stateMode: "UpdateInitialStateWithUseEffect",
    defaultState,
    submit,
    validate,
  });

  const [deleteRoleDialogData, setDeleteRoleDialogData] =
    useState<DeleteRoleDialogData | null>(null);
  const onClickDeleteRole = useCallback(() => {
    setDeleteRoleDialogData({
      roleID: role.id,
      roleKey: role.key,
      roleName: role.name ?? null,
    });
  }, [role.id, role.key, role.name]);
  const dismissDeleteRoleDialog = useCallback((isDeleted: boolean) => {
    setDeleteRoleDialogData(null);
    isDeletedRef.current = isDeleted;
  }, []);

  const exitIfDeleted = useCallback(() => {
    if (isDeletedRef.current) {
      navigate(`/project/${appID}/user-management/roles`, { replace: true });
    }
  }, [navigate, appID]);

  return (
    <>
      <RoleAndGroupsFormContainer form={form}>
        <RoleDetailsScreenSettingsForm onClickDeleteRole={onClickDeleteRole} />
      </RoleAndGroupsFormContainer>

      <DeleteRoleDialog
        onDismiss={dismissDeleteRoleDialog}
        onDismissed={exitIfDeleted}
        data={deleteRoleDialogData}
      />
    </>
  );
}

const GROUPS_LIST_COLUMNS = [
  GroupsListColumnKey.Name,
  GroupsListColumnKey.Key,
  GroupsListColumnKey.Action,
];

function RoleDetailsScreenGroupListContainer({
  role,
}: {
  role: RoleQueryNodeFragment;
}) {
  const {
    data: groupsQueryData,
    loading,
    error,
    refetch,
  } = useQuery<GroupsListQueryQuery, GroupsListQueryQueryVariables>(
    GroupsListQueryDocument,
    {
      variables: {
        pageSize: 0,
        searchKeyword: "",
      },
      fetchPolicy: "network-only",
    }
  );

  if (error != null) {
    return <ShowError error={error} onRetry={refetch} />;
  }

  if (loading) {
    return <ShowLoading />;
  }

  const totalCount = groupsQueryData?.groups?.totalCount ?? 0;

  if (totalCount === 0) {
    return <GroupsEmptyView />;
  }

  const roleGroups =
    role.groups?.edges?.flatMap<GroupsListItem>((edge) => {
      if (edge?.node != null) {
        return [edge.node];
      }
      return [];
    }) ?? [];

  return (
    <section className="flex-1-0-auto">
      <header className="h-9 mb-8">{/* TODO */}</header>
      <GroupsList groups={roleGroups} columns={GROUPS_LIST_COLUMNS} />
    </section>
  );
}

const RoleDetailsScreenLoaded: React.VFC<{
  role: RoleQueryNodeFragment;
  reload: ReturnType<typeof useRoleQuery>["refetch"];
}> = function RoleDetailsScreenLoaded({ role }) {
  const { renderToString } = useContext(MessageContext);

  const { selectedKey, onLinkClick } = usePivotNavigation([
    SETTINGS_KEY,
    GROUPS_KEY,
  ]);

  const breadcrumbs = useMemo<BreadcrumbItem[]>(() => {
    return [
      {
        to: "~/user-management/roles",
        label: <FormattedMessage id="RolesScreen.title" />,
      },
      { to: ".", label: role.name ?? role.key },
    ];
  }, [role]);

  return (
    <RoleAndGroupsLayout breadcrumbs={breadcrumbs}>
      <Pivot
        overflowBehavior="menu"
        selectedKey={selectedKey}
        onLinkClick={onLinkClick}
        className="mb-8"
      >
        <PivotItem
          itemKey={SETTINGS_KEY}
          headerText={renderToString("RoleDetailsScreen.tabs.settings")}
        />
        <PivotItem
          itemKey={GROUPS_KEY}
          headerText={renderToString("RoleDetailsScreen.tabs.groups")}
        />
      </Pivot>
      {selectedKey === GROUPS_KEY ? (
        <RoleDetailsScreenGroupListContainer role={role} />
      ) : (
        <RoleDetailsScreenSettingsFormContainer role={role} />
      )}
    </RoleAndGroupsLayout>
  );
};

const RoleDetailsScreen: React.VFC = function RoleDetailsScreen() {
  const { roleID } = useParams() as { roleID: string };
  const { role, loading, error, refetch } = useRoleQuery(roleID);

  if (error != null) {
    return <ShowError error={error} onRetry={refetch} />;
  }

  if (loading) {
    return <ShowLoading />;
  }

  if (role == null) {
    return <ShowLoading />;
  }

  return <RoleDetailsScreenLoaded role={role} reload={refetch} />;
};

export default RoleDetailsScreen;
