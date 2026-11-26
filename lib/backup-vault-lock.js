// CG-157 Resilient immutable backups: AWS Backup Vault Lock state from read-only exports (ListBackupVaults and
// ListRestoreJobs). Governance mode can be removed by users with sufficient IAM permissions; compliance mode can be
// changed or removed only until its LockDate (grace time of at least 3 days), after which the vault and its lock
// cannot be changed or deleted by any user or by AWS. Backups in a locked vault cannot be deleted until their
// lifecycle completes, so long or unbounded retention means persistent storage cost. The strategy is not relied on
// until a restore from the vault has actually succeeded.
import { fail } from './common.js';

const DAY = 86400000;
export const RESTORE_PROOF_DAYS = 90, LONG_RETENTION_DAYS = 3650;
export const MODE_AR = { unlocked: 'غير مقفل', governance: 'حوكمة (قابل للإزالة بصلاحيات IAM)', 'compliance-grace': 'امتثال — ضمن فترة السماح (قابل للإزالة حتى تاريخ القفل)', 'compliance-immutable': 'امتثال — غير قابل للتغيير ولا الحذف (حتى من AWS)' };
const ts = v => v === null || v === undefined || v === '' ? null : typeof v === 'number' ? new Date(v < 1e12 ? v * 1000 : v).toISOString() : new Date(v).toISOString();

export function parseVaults(json) {
  const list = (typeof json === 'string' ? JSON.parse(json) : json)?.BackupVaultList; fail(Array.isArray(list), 400, 'not_list_backup_vaults_export');
  return list.map(v => ({ name: String(v.BackupVaultName), arn: String(v.BackupVaultArn), type: String(v.VaultType || 'BACKUP_VAULT'), state: v.VaultState ? String(v.VaultState) : null, locked: v.Locked === true,
    lock_date: ts(v.LockDate), min_retention_days: v.MinRetentionDays ?? null, max_retention_days: v.MaxRetentionDays ?? null, recovery_points: Number(v.NumberOfRecoveryPoints || 0) }));
}

export function parseRestoreJobs(json) {
  const list = (typeof json === 'string' ? JSON.parse(json) : json)?.RestoreJobs; fail(Array.isArray(list), 400, 'not_list_restore_jobs_export');
  return list.map(j => ({ id: String(j.RestoreJobId), vault_arn: j.BackupVaultArn ? String(j.BackupVaultArn) : null, status: String(j.Status || ''), created: ts(j.CreationDate), completed: ts(j.CompletionDate), resource_type: j.ResourceType ? String(j.ResourceType) : null,
    test_plan: j.CreatedBy?.RestoreTestingPlanArn ? String(j.CreatedBy.RestoreTestingPlanArn) : null, validation: j.ValidationStatus ? String(j.ValidationStatus) : null }));
}

export function modeOf(v, now) {
  if (!v.locked) return 'unlocked';
  if (!v.lock_date) return 'governance'; // only compliance mode has a LockDate (ChangeableForDays)
  return Date.parse(v.lock_date) > now ? 'compliance-grace' : 'compliance-immutable';
}

export function assessVaults({ vaults, restores }, now = Date.now()) {
  return vaults.map(v => {
    const mode = modeOf(v, now), jobs = restores.filter(j => j.vault_arn === v.arn).sort((a, b) => String(b.created).localeCompare(String(a.created)));
    const ok = jobs.find(j => j.status === 'COMPLETED' && !/FAIL|TIMED_OUT/i.test(j.validation || '') && now - Date.parse(j.completed || j.created) <= RESTORE_PROOF_DAYS * DAY), last = jobs[0] || null;
    const restore = ok ? 'restore-proven' : last && /FAILED|ABORTED/.test(last.status) ? 'restore-failed' : 'restore-untested';
    const findings = [];
    if (mode === 'unlocked' && v.recovery_points) findings.push({ id: 'not-immutable', severity: 'medium', text: 'Backups in this vault can be deleted: no Vault Lock.', text_ar: 'يمكن حذف النسخ في هذه الخزنة: لا يوجد قفل.' });
    if (mode === 'governance') findings.push({ id: 'governance-removable', severity: 'low', text: 'Governance mode: users with sufficient IAM permissions can remove the lock.', text_ar: 'وضع الحوكمة: يمكن لمن يملك صلاحيات IAM كافية إزالة القفل.' });
    if (mode === 'compliance-grace') findings.push({ id: 'compliance-grace', severity: restore === 'restore-proven' ? 'low' : 'high', text: `Compliance lock becomes irreversible on ${v.lock_date.slice(0, 10)}${restore === 'restore-proven' ? '' : ' and no successful restore from this vault is recorded'}.`, text_ar: `يصبح قفل الامتثال نهائيًا في ${v.lock_date.slice(0, 10)}${restore === 'restore-proven' ? '' : ' ولا توجد استعادة ناجحة مسجلة من هذه الخزنة'}.` });
    if ((mode === 'compliance-grace' || mode === 'compliance-immutable') && (v.max_retention_days === null || v.max_retention_days > LONG_RETENTION_DAYS)) findings.push({ id: 'cost-risk', severity: 'medium', text: `Backups cannot be deleted before their lifecycle ends; maximum retention ${v.max_retention_days ?? 'not set'} days means persistent storage cost.`, text_ar: `لا يمكن حذف النسخ قبل انتهاء دورة حياتها؛ و${v.max_retention_days === null ? 'عدم تحديد أقصى احتفاظ' : `أقصى احتفاظ ${v.max_retention_days} يومًا`} يعني تكلفة تخزين مستمرة.` });
    if (restore === 'restore-failed') findings.push({ id: 'restore-failed', severity: 'high', text: 'The latest restore from this vault failed.', text_ar: 'فشلت آخر استعادة من هذه الخزنة.' });
    if (restore === 'restore-untested' && v.recovery_points) findings.push({ id: 'restore-untested', severity: 'medium', text: `No successful restore from this vault in the last ${RESTORE_PROOF_DAYS} days: do not rely on it yet.`, text_ar: `لا استعادة ناجحة من هذه الخزنة خلال آخر ${RESTORE_PROOF_DAYS} يومًا: لا يُعتمد عليها بعد.` });
    return { ...v, mode, mode_basis: v.locked ? (v.lock_date ? 'LockDate present (compliance mode)' : 'no LockDate (governance mode)') : null, restore, last_restore: last, proven_by: ok || null, reliable: restore === 'restore-proven' && mode !== 'unlocked', findings };
  });
}

export function vaultLockView(store, now = Date.now()) {
  const latest = new Map();
  for (const r of store.all("SELECT observed_at,payload FROM events WHERE kind='resilience.backup_vault_lock' ORDER BY observed_at,received_at")) { const d = JSON.parse(r.payload).details; latest.set(`${d.account_id}:${d.region}`, { ...d, observed_at: r.observed_at }); }
  return { scopes: [...latest.values()].map(d => ({ account_id: d.account_id, region: d.region, observed_at: d.observed_at, vaults: assessVaults(d, now) })), mode_ar: MODE_AR, restore_proof_days: RESTORE_PROOF_DAYS,
    reference: { id: 'AWS Backup Vault Lock', url: 'https://docs.aws.amazon.com/aws-backup/latest/devguide/vault-lock.html' },
    claim: 'Vault Lock is shown with its mode and what can still undo it. Compliance mode becomes irreversible at its lock date, even for the root user and AWS, and locked backups keep costing until their lifecycle ends. A vault is relied on only after a successful restore from it.',
    claim_ar: 'يُعرض قفل الخزنة بوضعه وبما يمكن أن يلغيه. ويصبح وضع الامتثال نهائيًا عند تاريخ القفل، حتى للمستخدم الجذر ولـ AWS، وتبقى تكلفة النسخ المقفلة حتى انتهاء دورة حياتها. ولا يُعتمد على خزنة إلا بعد استعادة ناجحة منها.' };
}
