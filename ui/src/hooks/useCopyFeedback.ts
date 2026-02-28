import { useCallback, useRef, useState } from 'react';

/**
 * Wraps the clipboard copy action with visual state so the caller can show
 * a "Copied ✓" indicator for a brief moment.
 *
 * Usage:
 *   const { copy, copied } = useCopyFeedback();
 *   <button onClick={() => copy(text)}>
 *     {copied ? 'Copied ✓' : 'Copy'}
 *   </button>
 */
export function useCopyFeedback(resetAfterMs = 1800) {
  const [copied, setCopied] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const copy = useCallback(
    async (text: string): Promise<boolean> => {
      try {
        await navigator.clipboard.writeText(text);
        setCopied(true);
        if (timer.current) clearTimeout(timer.current);
        timer.current = setTimeout(() => setCopied(false), resetAfterMs);
        return true;
      } catch {
        setCopied(false);
        return false;
      }
    },
    [resetAfterMs],
  );

  return { copy, copied } as const;
}
