<script lang="ts">
  import TransferCenter from './TransferCenter.svelte';

  interface Props {
    open?: boolean;
    onClose: () => void;
  }

  let { open = $bindable(false), onClose }: Props = $props();
</script>

{#if open}
  <div class="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="tc-modal-title">
    <div class="modal-content">
      <div class="modal-header">
        <div class="header-title">
          <h2 id="tc-modal-title">Transfer Center</h2>
        </div>
        <div class="header-actions">
          <button class="btn-close" onclick={onClose} aria-label="Close">✕</button>
        </div>
      </div>
      <TransferCenter />
    </div>
  </div>
{/if}

<style>
  .modal-backdrop {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.6);
    display: flex;
    align-items: flex-start;
    justify-content: center;
    z-index: 50;
    padding: 2rem 1rem;
    overflow-y: auto;
  }
  .modal-content {
    background: var(--surface, #1b1b1b);
    border: 1px solid var(--border, #2e2e2e);
    border-radius: 14px;
    max-width: 42rem;
    width: 100%;
    padding: 1.25rem;
  }
  .modal-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 1rem;
  }
  .header-title h2 {
    margin: 0;
    font-size: 1.15rem;
  }
  .btn-close {
    background: none;
    border: none;
    font-size: 1.1rem;
    cursor: pointer;
    color: inherit;
  }
</style>
