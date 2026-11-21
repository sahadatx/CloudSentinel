import { Icon } from "./Icon";

type ViewActionProps = {
  label: string;
  onClick: () => void;
  disabled?: boolean;
};

export function ViewAction({
  label,
  onClick,
  disabled = false,
}: ViewActionProps) {
  return (
    <button
      type="button"
      className="scan-view-action"
      aria-label={label}
      disabled={disabled}
      onClick={onClick}
    >
      <Icon name="eye" />
      <span>View</span>
    </button>
  );
}
