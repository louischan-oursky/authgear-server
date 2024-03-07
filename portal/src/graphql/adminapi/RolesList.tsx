import React, { useCallback, useContext, useMemo } from "react";
import cn from "classnames";
import { RolesListFragment } from "./query/rolesListQuery.generated";
import useDelayedValue from "../../hook/useDelayedValue";
import {
  ColumnActionsMode,
  DetailsListLayoutMode,
  DetailsRow,
  IColumn,
  IDetailsRowProps,
  SelectionMode,
  ShimmeredDetailsList,
  Text,
} from "@fluentui/react";
import styles from "./RolesList.module.css";
import { useSystemConfig } from "../../context/SystemConfigContext";
import { useParams } from "react-router-dom";
import { Context, FormattedMessage } from "@oursky/react-messageformat";
import Link from "../../Link";
import ActionButton from "../../ActionButton";

interface RolesListProps {
  className?: string;
  isSearch: boolean;
  loading: boolean;
  roles: RolesListFragment | null;
  offset: number;
  pageSize: number;
  totalCount?: number;
  onChangeOffset?: (offset: number) => void;
}

interface RoleListItem {
  id: string;
  key: string;
  name: string | null;
  description: string | null;
}

const isRoleListItem = (value: unknown): value is RoleListItem => {
  if (!(value instanceof Object)) {
    return false;
  }
  return "key" in value && "id" in value;
};

const RolesList: React.VFC<RolesListProps> = function RolesList(props) {
  const { className, loading: rawLoading } = props;
  const edges = props.roles?.edges;
  const loading = useDelayedValue(rawLoading, 500);
  const { renderToString } = useContext(Context);
  const { themes } = useSystemConfig();
  const { appID } = useParams() as { appID: string };
  const columns: IColumn[] = [
    {
      key: "name",
      fieldName: "name",
      name: renderToString("RolesList.column.name"),
      flexGrow: 1,
      minWidth: 260,
      columnActionsMode: ColumnActionsMode.disabled,
    },
    {
      key: "key",
      fieldName: "key",
      name: renderToString("RolesList.column.key"),
      flexGrow: 1,
      minWidth: 260,
      columnActionsMode: ColumnActionsMode.disabled,
    },
    {
      key: "description",
      fieldName: "description",
      name: renderToString("RolesList.column.description"),
      minWidth: 489,
      columnActionsMode: ColumnActionsMode.disabled,
    },
    {
      key: "action",
      fieldName: "action",
      name: renderToString("RolesList.column.action"),
      minWidth: 67,
      columnActionsMode: ColumnActionsMode.disabled,
    },
  ];
  const items: RoleListItem[] = useMemo(() => {
    const items = [];
    if (edges != null) {
      for (const edge of edges) {
        const node = edge?.node;
        if (node != null) {
          items.push({
            id: node.id,
            name: node.name ?? null,
            key: node.key,
            description: node.description ?? null,
          });
        }
      }
    }
    return items;
  }, [edges]);

  const onRenderRoleRow = React.useCallback(
    (props?: IDetailsRowProps) => {
      if (props == null) {
        return null;
      }
      const targetPath = isRoleListItem(props.item)
        ? `/project/${appID}/user-management/roles/${props.item.id}/details`
        : ".";
      return (
        <Link to={targetPath}>
          <DetailsRow {...props} />
        </Link>
      );
    },
    [appID]
  );
  const onRenderTextActionButtonText = useCallback(() => {
    return (
      <Text className={styles.actionButtonText} theme={themes.destructive}>
        <FormattedMessage id="RolesList.delete-role" />
      </Text>
    );
  }, [themes.destructive]);

  const onRenderRoleItemColumn = useCallback(
    (item: RoleListItem, _index?: number, column?: IColumn) => {
      switch (column?.key) {
        case "description":
          return (
            <div className={styles.cell}>
              <div className={styles.description}>
                {item[column.key as keyof RoleListItem] ?? ""}
              </div>
            </div>
          );
        case "action": {
          return (
            <div className={styles.cell}>
              <ActionButton
                onRenderText={onRenderTextActionButtonText}
                className={styles.actionButton}
                theme={themes.destructive}
                onClick={(e) => {
                  e.preventDefault();
                  e.stopPropagation();
                  alert("TODO");
                }}
              />
            </div>
          );
        }
        default:
          return (
            <div className={styles.cell}>
              <div className={styles.cellText}>
                {item[column?.key as keyof RoleListItem] ?? ""}
              </div>
            </div>
          );
      }
    },
    [themes.destructive, onRenderTextActionButtonText]
  );
  return (
    <>
      <div className={cn(styles.root, className)}>
        <div className={styles.listWrapper}>
          <ShimmeredDetailsList
            enableShimmer={loading}
            enableUpdateAnimations={false}
            onRenderRow={onRenderRoleRow}
            onRenderItemColumn={onRenderRoleItemColumn}
            selectionMode={SelectionMode.none}
            layoutMode={DetailsListLayoutMode.justified}
            items={items}
            columns={columns}
          />
        </div>
      </div>
    </>
  );
};

export default RolesList;
