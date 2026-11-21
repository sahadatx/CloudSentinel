import { useEffect, useId, useRef } from "react";
import type { ReactNode } from "react";
import { Icon } from "./Icon";

let activeDrawers = 0;
let scrollStyles: { root: string; body: string } | undefined;

function lockDocumentScroll() {
  if (activeDrawers === 0) {
    scrollStyles = {
      root: document.documentElement.style.overflow,
      body: document.body.style.overflow,
    };
    document.documentElement.style.overflow = "hidden";
    document.body.style.overflow = "hidden";
  }
  activeDrawers += 1;

  return () => {
    activeDrawers -= 1;
    if (activeDrawers === 0 && scrollStyles) {
      document.documentElement.style.overflow = scrollStyles.root;
      document.body.style.overflow = scrollStyles.body;
      scrollStyles = undefined;
    }
  };
}

export function RightDrawer({
  title,
  description,
  onClose,
  children,
  className = "",
}: {
  title: string;
  description?: string;
  onClose: () => void;
  children: ReactNode;
  className?: string;
}) {
  const dialogRef = useRef<HTMLDialogElement>(null);
  const titleRef = useRef<HTMLHeadingElement>(null);
  const titleId = useId();
  const descriptionId = useId();

  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;

    const previouslyFocusedElement = document.activeElement;
    const unlockScroll = lockDocumentScroll();
    dialog.showModal();
    if (!dialog.querySelector("[autofocus]")) {
      titleRef.current?.focus({ preventScroll: true });
    }

    return () => {
      dialog.close();
      unlockScroll();
      const openDialogs = Array.from(document.querySelectorAll("dialog[open]"));
      if (
        previouslyFocusedElement instanceof HTMLElement &&
        previouslyFocusedElement.isConnected &&
        (openDialogs.length === 0 ||
          openDialogs.some((item) => item.contains(previouslyFocusedElement)))
      ) {
        previouslyFocusedElement.focus({ preventScroll: true });
      }
    };
  }, []);

  return (
    <dialog
      ref={dialogRef}
      className="drawer-backdrop"
      aria-labelledby={titleId}
      aria-describedby={description ? descriptionId : undefined}
      onCancel={(event) => {
        event.preventDefault();
        onClose();
      }}
      onMouseDown={(event) => {
        if (event.button === 0 && event.target === event.currentTarget)
          onClose();
      }}
    >
      <section className={`right-drawer ${className}`}>
        <header className="drawer-header">
          <div>
            <h2 ref={titleRef} id={titleId} tabIndex={-1}>
              {title}
            </h2>
            {description && <p id={descriptionId}>{description}</p>}
          </div>
          <button
            className="quiet-button"
            type="button"
            onClick={onClose}
            aria-label="Close drawer"
            title="Close drawer"
          >
            <Icon name="close" />
          </button>
        </header>
        <div className="drawer-body">{children}</div>
      </section>
    </dialog>
  );
}

export function DrawerFact({
  label,
  value,
}: {
  label: string;
  value: ReactNode;
}) {
  return (
    <div className="drawer-fact">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}
