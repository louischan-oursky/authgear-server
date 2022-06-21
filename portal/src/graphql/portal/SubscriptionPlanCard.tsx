import React from "react";
import {
  useTheme,
  Text,
  PrimaryButton,
  DefaultButton,
  ThemeProvider,
  PartialTheme,
} from "@fluentui/react";
import { FormattedMessage } from "@oursky/react-messageformat";
import styles from "./SubscriptionPlanCard.module.scss";

interface CardProps {
  isActive: boolean;
  tag?: React.ReactNode;
  children?: React.ReactNode;
}

function Card(props: CardProps) {
  const { isActive, tag, children } = props;
  const theme = useTheme();
  return (
    <div
      className={styles.card}
      style={{
        borderColor: isActive
          ? theme.palette.themePrimary
          : theme.semanticColors.bodyDivider,
      }}
    >
      {tag != null ? tag : null}
      {children}
    </div>
  );
}

export interface CardTagProps {
  children?: React.ReactNode;
}

export function CardTag(props: CardTagProps): React.ReactElement {
  const { children } = props;
  const theme = useTheme();

  return (
    <div
      className={styles.cardTag}
      style={{
        backgroundColor: theme.semanticColors.primaryButtonBackground,
      }}
    >
      <Text
        block={true}
        styles={{
          root: {
            color: theme.semanticColors.primaryButtonText,
          },
        }}
      >
        {children}
      </Text>
    </div>
  );
}

export interface CardTitleProps {
  children?: React.ReactNode;
}

export function CardTitle(props: CardTitleProps): React.ReactElement {
  const { children } = props;
  return (
    <Text block={true} variant="xLarge">
      {children}
    </Text>
  );
}

export interface CardTaglineProps {
  children?: React.ReactNode;
}

export function CardTagline(props: CardTaglineProps): React.ReactElement {
  const { children } = props;
  return (
    <Text block={true} className={styles.cardTagline}>
      {children}
    </Text>
  );
}

interface BasePriceSectionProps {
  children?: React.ReactNode;
}

function BasePriceSection(props: BasePriceSectionProps) {
  const { children } = props;
  return <div className={styles.basePriceSection}>{children}</div>;
}

export interface BasePriceTagProps {
  children?: React.ReactNode;
}

export function BasePriceTag(props: BasePriceTagProps): React.ReactElement {
  const { children } = props;
  return (
    <Text block={true} variant="xLarge" className={styles.basePriceTag}>
      {children}
    </Text>
  );
}

export interface MAURestrictionProps {
  children?: React.ReactNode;
}

export function MAURestriction(props: MAURestrictionProps): React.ReactElement {
  const { children } = props;
  return (
    <Text block={true} className={styles.mauRestriction}>
      {children}
    </Text>
  );
}

interface UsagePriceTagSectionProps {
  children?: React.ReactNode;
}

function UsagePriceTagSection(props: UsagePriceTagSectionProps) {
  const { children } = props;
  const theme = useTheme();
  return (
    <div
      className={styles.usagePriceTagSection}
      style={{
        backgroundColor: theme.semanticColors.bodyBackgroundHovered,
      }}
    >
      {children}
    </div>
  );
}

export interface UsagePriceTagProps {
  children?: React.ReactNode;
}

export function UsagePriceTag(props: UsagePriceTagProps): React.ReactElement {
  const { children } = props;
  return <Text block={true}>{children}</Text>;
}

export interface CTAProps {
  variant: "upgrade" | "downgrade" | "current";
}

const DOWNGRADE_BUTTON_THEME: PartialTheme = {
  semanticColors: {
    buttonText: "#C8C8C8",
    buttonBorder: "#C8C8C8",
  },
};

const CURRENT_BUTTON_THEME: PartialTheme = {
  semanticColors: {
    buttonTextDisabled: "#C8C8C8",
    buttonBackgroundDisabled: "white",
    disabledBackground: "#C8C8C8",
  },
};

export function CTA(props: CTAProps): React.ReactElement {
  const { variant } = props;
  if (variant === "upgrade") {
    return (
      <PrimaryButton className={styles.cta}>
        <FormattedMessage id="SubscriptionPlanCard.label.upgrade" />
      </PrimaryButton>
    );
  }
  if (variant === "downgrade") {
    return (
      <ThemeProvider theme={DOWNGRADE_BUTTON_THEME}>
        <DefaultButton className={styles.cta}>
          <FormattedMessage id="SubscriptionPlanCard.label.downgrde" />
        </DefaultButton>
      </ThemeProvider>
    );
  }
  return (
    <ThemeProvider theme={CURRENT_BUTTON_THEME}>
      <DefaultButton className={styles.cta} disabled={true}>
        <FormattedMessage id="SubscriptionPlanCard.label.current" />
      </DefaultButton>
    </ThemeProvider>
  );
}

function Separator() {
  const theme = useTheme();
  return (
    <div
      className={styles.separator}
      style={{
        backgroundColor: theme.semanticColors.bodyDivider,
      }}
    />
  );
}

interface PlanDetailsSectionProps {
  children?: React.ReactNode;
}

function PlanDetailsSection(props: PlanDetailsSectionProps) {
  const { children } = props;
  return <div className={styles.planDetailsSection}>{children}</div>;
}

export interface PlanDetailsTitleProps {
  children?: React.ReactNode;
}

export function PlanDetailsTitle(
  props: PlanDetailsTitleProps
): React.ReactElement {
  const { children } = props;
  const theme = useTheme();
  return (
    <Text
      block={true}
      className={styles.planDetailsTitle}
      style={{
        color: theme.semanticColors.link,
      }}
    >
      {children}
    </Text>
  );
}

export interface PlanDetailsLineProps {
  children?: React.ReactNode;
}

export function PlanDetailsLine(
  props: PlanDetailsLineProps
): React.ReactElement {
  const { children } = props;
  const theme = useTheme();
  return (
    <Text
      block={true}
      style={{
        color: theme.semanticColors.link,
      }}
    >
      {children}
    </Text>
  );
}

export interface SubscriptionPlanCardProps {
  isCurrentPlan: boolean;
  cardTag?: React.ReactNode;
  cardTitle: React.ReactNode;
  cardTagline: React.ReactNode;
  basePriceTag: React.ReactNode;
  mauRestriction: React.ReactNode;
  usagePriceTags: React.ReactNode;
  cta: React.ReactNode;
  planDetailsTitle: React.ReactNode;
  planDetailsLines: React.ReactNode;
}

function SubscriptionPlanCard(
  props: SubscriptionPlanCardProps
): React.ReactElement | null {
  const {
    isCurrentPlan,
    cardTag,
    cardTitle,
    cardTagline,
    basePriceTag,
    mauRestriction,
    usagePriceTags,
    cta,
    planDetailsTitle,
    planDetailsLines,
  } = props;
  return (
    <Card tag={cardTag} isActive={isCurrentPlan}>
      <div>
        {cardTitle}
        {cardTagline}
        <BasePriceSection>
          {basePriceTag}
          {mauRestriction}
        </BasePriceSection>
      </div>
      <div className={styles.cardMiddleSection}>
        <UsagePriceTagSection>{usagePriceTags}</UsagePriceTagSection>
        {cta}
      </div>
      <div>
        <Separator />
        <PlanDetailsSection>
          {planDetailsTitle}
          {planDetailsLines}
        </PlanDetailsSection>
      </div>
    </Card>
  );
}

export default SubscriptionPlanCard;
