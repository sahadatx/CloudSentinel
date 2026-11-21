import { Icon } from "../shared/Icon";

export function AuthBrand() {
  return (
    <>
      <span className="login-brand-mark" aria-hidden="true">
        <Icon name="shield" />
      </span>
      <span>
        CLOUDSENTINEL<small>SECURITY OPERATIONS</small>
      </span>
    </>
  );
}
