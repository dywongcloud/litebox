'use client';

/**
 * Shared form field primitives used by every entity's create/edit modal.
 *
 * Plain, uncontrolled inputs (`defaultValue`, not `value`): the surrounding
 * forms are submitted via Server Actions and re-rendered from the action's
 * returned state, so there is no need for per-keystroke controlled state here
 * -- that would only add re-renders without a behavioural benefit.
 */

export function TextField({
  label,
  name,
  defaultValue,
  required,
  errors,
  className,
  type = 'text',
  maxLength = 300,
}: {
  label: string;
  name: string;
  defaultValue?: string;
  required?: boolean;
  errors?: Record<string, string[]>;
  className?: string;
  type?: string;
  maxLength?: number;
}) {
  return (
    <label className={className}>
      {label}
      <input type={type} name={name} defaultValue={defaultValue ?? ''} required={required} maxLength={maxLength} />
      {errors?.[name] ? <span className="field-error">{errors[name][0]}</span> : null}
    </label>
  );
}

export function TextAreaField({
  label,
  name,
  defaultValue,
  hint,
  errors,
  className,
}: {
  label: string;
  name: string;
  defaultValue?: string;
  hint?: string;
  errors?: Record<string, string[]>;
  className?: string;
}) {
  return (
    <label className={className}>
      {label}
      <textarea name={name} defaultValue={defaultValue ?? ''} maxLength={20000} />
      {hint ? <span className="small">{hint}</span> : null}
      {errors?.[name] ? <span className="field-error">{errors[name][0]}</span> : null}
    </label>
  );
}

export function SelectField<T extends string>({
  label,
  name,
  defaultValue,
  options,
  className,
}: {
  label: string;
  name: string;
  defaultValue: T;
  options: readonly T[];
  className?: string;
}) {
  return (
    <label className={className}>
      {label}
      <select name={name} defaultValue={defaultValue}>
        {options.map((option) => (
          <option key={option} value={option}>
            {option}
          </option>
        ))}
      </select>
    </label>
  );
}
