package com.sitr.vault;

import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.database.Cursor;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.hardware.fingerprint.FingerprintManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.os.Handler;
import android.os.Looper;
import android.os.PersistableBundle;
import android.provider.OpenableColumns;
import android.provider.Settings;
import android.text.InputType;
import android.view.Gravity;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageButton;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.core.content.FileProvider;
import androidx.fragment.app.FragmentActivity;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public final class MainActivity extends FragmentActivity {
    private static final int BG = Color.BLACK;
    private static final int PANEL = Color.rgb(18, 23, 31);
    private static final int PANEL_HI = Color.rgb(31, 40, 52);
    private static final int BORDER = Color.rgb(52, 64, 79);
    private static final int BLUE = Color.rgb(42, 119, 232);
    private static final int TEXT = Color.rgb(239, 243, 248);
    private static final int MUTED = Color.rgb(163, 176, 192);
    private static final int[] PROJECT_COLORS = {
            Color.rgb(45, 91, 150), Color.rgb(72, 97, 139), Color.rgb(71, 111, 101),
            Color.rgb(126, 85, 115), Color.rgb(133, 94, 65), Color.rgb(76, 107, 137),
            Color.rgb(97, 89, 145), Color.rgb(54, 119, 133)
    };
    private static final String GENERAL_VAULT_ID = "general-vault-v2";
    private static final int MIN_PASSWORD_CHARS = VaultCrypto.MIN_PASSWORD_CHARS;

    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final SecureRandom random = new SecureRandom();

    private ActivityResultLauncher<String[]> projectFilePicker;
    private ActivityResultLauncher<String[]> secretFilePicker;
    private ActivityResultLauncher<String> fileExportPicker;
    private ActivityResultLauncher<String> bulkExportPicker;
    private SecretKeySpec workspaceKey;
    private WorkspaceData workspace;
    private boolean workspaceUnlocked;
    private boolean activityResumed;
    private boolean fingerprintInProgress;
    private boolean needsUnlockOnResume;
    private boolean externalPickerPending;
    private boolean projectFileImportBusy;
    private boolean fileOperationBusy;
    private boolean lockAfterFileOperation;
    private CancellationSignal fingerprintCancellation;
    private AlertDialog fingerprintDialog;
    private byte[] pendingWorkspaceKey;
    private char[] pendingVaultPassword;
    private Runnable externalPickerTimeout;

    private Project currentProject;
    private String currentProjectVersionScreenId;
    private VaultSession currentVaultSession;
    private String currentVaultOwnerId;
    private String currentVaultLabel;
    private boolean currentVaultIsGeneral;
    private String pendingProjectId;
    private String pendingProjectVersionId;
    private String pendingExportOwnerId;
    private VaultAttachment pendingExportAttachment;
    private SecretKey pendingExportKey;
    private List<VaultAttachment> pendingBulkExportAttachments;
    private String pendingBulkExportOwnerId;
    private SecretKey pendingBulkExportKey;
    private String pendingBulkExportProjectId;
    private String pendingBulkExportVersionId;
    private List<VaultAttachment> pendingBulkAttachFiles;
    private String pendingBulkAttachProjectId;
    private String pendingBulkAttachVersionId;
    private final Set<String> selectedProjectFileIds = new LinkedHashSet<>();
    private Uri pendingExternalOpenUri;
    private VaultSession pendingSecretAttachmentSession;
    private String pendingSecretAttachmentOwnerId;
    private String editorVaultOwnerId;
    private List<VaultAttachment> editorAttachments;
    private List<VaultAttachment> editorNewAttachments;
    private List<VaultAttachment> editorRemovedAttachments;
    private LinearLayout editorAttachmentList;
    private boolean editorCommitDone;
    private boolean editorFileImportBusy;
    private AlertDialog activeSensitiveDialog;
    private final List<EditText> sensitiveInputs = new ArrayList<>();

    private TextView projectFileStatus;
    private TextView vaultStatus;

    private interface FingerprintSuccess {
        void onAuthenticated(Cipher cipher);
    }

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        getWindow().setStatusBarColor(BG);
        getWindow().setNavigationBarColor(BG);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        projectFilePicker = registerForActivityResult(
                new ActivityResultContracts.OpenMultipleDocuments(), this::onProjectFilesSelected);
        secretFilePicker = registerForActivityResult(
                new ActivityResultContracts.OpenMultipleDocuments(), this::onSecretFilesSelected);
        fileExportPicker = registerForActivityResult(
                new ActivityResultContracts.CreateDocument("*/*"), this::onExportDestinationSelected);
        bulkExportPicker = registerForActivityResult(
                new ActivityResultContracts.CreateDocument("application/zip"), this::onBulkExportDestinationSelected);
        LocalFileStore.cleanupTemporaryFiles(this);
        showEntry();
    }

    @Override protected void onStart() {
        super.onStart();
        if (needsUnlockOnResume && !fileOperationBusy && !fingerprintInProgress && DeviceSecurity.isConfigured(this)) {
            needsUnlockOnResume = false;
            revokePendingExternalOpen();
            LocalFileStore.cleanupTemporaryFiles(this);
            showLockScreen("أُقفلت مساحة العمل عند مغادرة التطبيق.");
            beginWorkspaceUnlock();
        }
    }

    @Override protected void onResume() {
        super.onResume();
        activityResumed = true;
    }

    @Override protected void onPause() {
        activityResumed = false;
        super.onPause();
    }

    @Override protected void onStop() {
        super.onStop();
        if (workspaceUnlocked && !externalPickerPending && !fingerprintInProgress) {
            needsUnlockOnResume = true;
            if (fileOperationBusy) lockAfterFileOperation = true;
            else lockWorkspace();
        }
    }

    @Override protected void onDestroy() {
        cancelExternalPickerTimeout();
        cancelFingerprintPrompt();
        clearSensitiveUi();
        destroyVaultSession();
        clearWorkspaceKey();
        clearPendingBulkExport();
        clearPendingBulkAttach();
        selectedProjectFileIds.clear();
        if (pendingWorkspaceKey != null) Arrays.fill(pendingWorkspaceKey, (byte) 0);
        if (pendingVaultPassword != null) Arrays.fill(pendingVaultPassword, '\0');
        worker.shutdownNow();
        super.onDestroy();
    }

    @Override public void onBackPressed() {
        if (currentVaultSession != null) {
            closeVault();
        } else if (currentProject != null) {
            currentProject = null;
            showHome();
        } else if (workspaceUnlocked) {
            lockWorkspace();
            needsUnlockOnResume = false;
            showLockScreen("قُفلت مساحة العمل.");
        } else {
            super.onBackPressed();
        }
    }

    private void showEntry() {
        if (!DeviceSecurity.isFingerprintReady(this)) {
            showFingerprintUnavailable();
        } else if (DeviceSecurity.isConfigured(this)) {
            showLockScreen("استخدم بصمة الإصبع لفتح مشاريعك.");
            beginWorkspaceUnlock();
        } else {
            showFirstRunSetup();
        }
    }

    private void showFingerprintUnavailable() {
        LinearLayout screen = baseScreen();
        addBrand(screen);
        addText(screen, "بصمة الإصبع مطلوبة", 24, TEXT, true, 0, 12);
        addText(screen, "فعّل بصمة الإصبع من إعدادات أمان الجهاز ثم افتح سِتر مجددًا. لا يستخدم التطبيق التعرّف على الوجه أو كلمة مرور بديلة لدخول المشاريع.",
                15, MUTED, false, 0, 22);
        Button retry = button("إعادة المحاولة", BLUE, Color.WHITE);
        retry.setOnClickListener(v -> showEntry());
        screen.addView(retry, margins(0, 10, 0, 0));
        setContentView(screen);
    }

    private void showFirstRunSetup() {
        LinearLayout screen = baseScreen();
        addBrand(screen);
        addText(screen, "ابدأ ببصمة الإصبع", 25, TEXT, true, 4, 12);
        addText(screen, "ستُحمى أسماء المشاريع والملفات محليًا بتشفير، ولن تُرفع إلى أي خادم. سجّل بصمة إصبع على هذا الجهاز لبدء الاستخدام.",
                15, MUTED, false, 0, 18);
        Button setup = button("تفعيل سِتر بالبصمة", BLUE, Color.WHITE);
        setup.setOnClickListener(v -> beginWorkspaceSetup());
        screen.addView(setup, margins(0, 12, 0, 0));
        addText(screen, "بعد فتح التطبيق، لكل خزنة أسرار كلمة مرور مستقلة بالإضافة إلى بصمة الإصبع.",
                13, MUTED, false, 22, 0);
        setContentView(screen);
    }

    private void showLockScreen(String message) {
        LinearLayout screen = baseScreen();
        addBrand(screen);
        addText(screen, "مساحة عملك مقفلة", 24, TEXT, true, 2, 10);
        addText(screen, message, 14, MUTED, false, 0, 18);
        Button unlock = button("فتح ببصمة الإصبع", BLUE, Color.WHITE);
        unlock.setOnClickListener(v -> beginWorkspaceUnlock());
        screen.addView(unlock, margins(0, 8, 0, 0));
        setContentView(screen);
    }

    private void beginWorkspaceSetup() {
        if (!DeviceSecurity.isFingerprintReady(this)) {
            showFingerprintUnavailable();
            return;
        }
        try {
            pendingWorkspaceKey = new byte[32];
            random.nextBytes(pendingWorkspaceKey);
            Cipher cipher = DeviceSecurity.newSetupCipher();
            requestFingerprint(cipher, "سجّل بصمة إصبعك لتفعيل قفل سِتر", this::finishWorkspaceSetup, () -> {
                if (pendingWorkspaceKey != null) Arrays.fill(pendingWorkspaceKey, (byte) 0);
                pendingWorkspaceKey = null;
                showFirstRunSetup();
            });
        } catch (Exception e) {
            if (pendingWorkspaceKey != null) Arrays.fill(pendingWorkspaceKey, (byte) 0);
            pendingWorkspaceKey = null;
            showFirstRunSetup();
            toast("تعذّر إعداد مفتاح الحماية. تحقّق من إعداد بصمة الإصبع وحاول مجددًا.");
        }
    }

    private void beginWorkspaceUnlock() {
        if (!DeviceSecurity.isFingerprintReady(this)) {
            showFingerprintUnavailable();
            return;
        }
        try {
            requestFingerprint(DeviceSecurity.newUnlockCipher(this), "ضع إصبعك على مستشعر البصمة لفتح سِتر",
                    this::finishWorkspaceUnlock, () -> showLockScreen("لم تُفتح مساحة العمل. أعد المحاولة ببصمة الإصبع."));
        } catch (Exception e) {
            showLockScreen("تعذّر تهيئة قفل البصمة. تحقّق من إعدادات الجهاز.");
        }
    }

    private void requestFingerprint(Cipher cipher, String reason, FingerprintSuccess success, Runnable failure) {
        FingerprintManager manager = (FingerprintManager) getSystemService(Context.FINGERPRINT_SERVICE);
        if (manager == null || !DeviceSecurity.isFingerprintReady(this)) {
            if (failure != null) failure.run();
            showFingerprintUnavailable();
            return;
        }
        fingerprintInProgress = true;
        TextView message = text(reason + "\n\nأبقِ إصبعك على المستشعر.", 15, TEXT, false);
        message.setPadding(dp(8), dp(8), dp(8), dp(8));
        fingerprintDialog = new AlertDialog.Builder(this)
                .setTitle("التحقق ببصمة الإصبع")
                .setView(message)
                .setNegativeButton("إلغاء", (dialog, which) -> {
                    if (fingerprintCancellation != null) fingerprintCancellation.cancel();
                })
                .create();
        fingerprintDialog.setCancelable(false);
        fingerprintDialog.show();
        fingerprintCancellation = new CancellationSignal();
        final boolean[] completed = {false};
        try {
            manager.authenticate(new FingerprintManager.CryptoObject(cipher), fingerprintCancellation, 0,
                    new FingerprintManager.AuthenticationCallback() {
                        @Override public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
                            mainHandler.post(() -> {
                                if (completed[0]) return;
                                completed[0] = true;
                                finishFingerprintPrompt();
                                Cipher authorized = result.getCryptoObject() == null ? null : result.getCryptoObject().getCipher();
                                if (authorized == null) {
                                    if (failure != null) failure.run();
                                    toast("تعذّر إتمام التحقق المشفر.");
                                } else {
                                    success.onAuthenticated(authorized);
                                }
                            });
                        }

                        @Override public void onAuthenticationFailed() {
                            mainHandler.post(() -> {
                                if (!completed[0] && fingerprintDialog != null && fingerprintDialog.isShowing()) {
                                    message.setText("لم تتطابق البصمة. حاول مرة أخرى وأبقِ إصبعك على المستشعر.");
                                }
                            });
                        }

                        @Override public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
                            mainHandler.post(() -> {
                                if (!completed[0] && fingerprintDialog != null && fingerprintDialog.isShowing()) {
                                    message.setText(helpString == null ? "حاول وضع إصبعك على المستشعر مرة أخرى." : helpString);
                                }
                            });
                        }

                        @Override public void onAuthenticationError(int errorCode, CharSequence errString) {
                            mainHandler.post(() -> {
                                if (completed[0]) return;
                                completed[0] = true;
                                finishFingerprintPrompt();
                                if (failure != null) failure.run();
                                if (errorCode != FingerprintManager.FINGERPRINT_ERROR_CANCELED) {
                                    toast("تعذّر التحقق ببصمة الإصبع. حاول مرة أخرى.");
                                }
                            });
                        }
                    }, mainHandler);
        } catch (Exception e) {
            completed[0] = true;
            finishFingerprintPrompt();
            if (failure != null) failure.run();
            toast("لم يستطع الجهاز تشغيل مستشعر البصمة.");
        }
    }

    private void finishFingerprintPrompt() {
        fingerprintInProgress = false;
        fingerprintCancellation = null;
        if (fingerprintDialog != null && fingerprintDialog.isShowing()) fingerprintDialog.dismiss();
        fingerprintDialog = null;
    }

    private void cancelFingerprintPrompt() {
        if (fingerprintCancellation != null) fingerprintCancellation.cancel();
        finishFingerprintPrompt();
    }

    private void finishWorkspaceSetup(Cipher authorizedCipher) {
        byte[] rawKey = pendingWorkspaceKey;
        pendingWorkspaceKey = null;
        if (rawKey == null) return;
        SecretKeySpec key = new SecretKeySpec(rawKey, "AES");
        WorkspaceData empty = new WorkspaceData();
        worker.execute(() -> {
            Exception failure = null;
            try {
                DeviceSecurity.saveWrappedWorkspaceKey(this, authorizedCipher, rawKey);
                WorkspaceStore.save(this, key, empty);
            } catch (Exception e) {
                failure = e;
                DeviceSecurity.clear(this);
                WorkspaceStore.deleteWorkspace(this);
            } finally {
                Arrays.fill(rawKey, (byte) 0);
            }
            Exception error = failure;
            runOnUiThread(() -> {
                if (error != null) {
                    workspaceKey = null;
                    showFirstRunSetup();
                    toast("تعذّر حفظ مساحة العمل المشفرة. حاول مرة أخرى.");
                } else {
                    workspaceKey = key;
                    workspace = empty;
                    workspaceUnlocked = true;
                    needsUnlockOnResume = false;
                    showHome();
                }
            });
        });
    }

    private void finishWorkspaceUnlock(Cipher authorizedCipher) {
        final SecretKeySpec key;
        try {
            byte[] rawKey = DeviceSecurity.unwrapWorkspaceKey(this, authorizedCipher);
            key = new SecretKeySpec(rawKey, "AES");
            Arrays.fill(rawKey, (byte) 0);
        } catch (Exception e) {
            showLockScreen("تعذّر فك مفتاح مساحة العمل. لا يمكن عرض البيانات.");
            return;
        }
        worker.execute(() -> {
            WorkspaceData loaded = null;
            Exception failure = null;
            try { loaded = WorkspaceStore.load(this, key); }
            catch (Exception e) { failure = e; }
            WorkspaceData result = loaded;
            Exception error = failure;
            runOnUiThread(() -> {
                if (error != null || result == null) {
                    workspaceKey = null;
                    showLockScreen("تعذّر فتح ملف المشاريع المشفر. لم تُعرض أي بيانات.");
                    toast("قد يكون الملف تالفًا أو أن إعداد بصمة الجهاز تغيّر.");
                } else {
                    workspaceKey = key;
                    workspace = result;
                    workspaceUnlocked = true;
                    needsUnlockOnResume = false;
                    currentProject = null;
                    showHome();
                }
            });
        });
    }

    private void requestReauthentication(Runnable onSuccess, Runnable onFailure) {
        if (!workspaceUnlocked || workspaceKey == null) {
            if (onFailure != null) onFailure.run();
            return;
        }
        try {
            Cipher cipher = DeviceSecurity.newUnlockCipher(this);
            requestFingerprint(cipher, "أكّد بصمة الإصبع لتفعيل الخزنة", authorized -> {
                byte[] raw = null;
                byte[] expected = null;
                boolean matches = false;
                try {
                    raw = DeviceSecurity.unwrapWorkspaceKey(this, authorized);
                    expected = workspaceKey.getEncoded();
                    matches = MessageDigest.isEqual(raw, expected);
                } catch (Exception ignored) { }
                finally {
                    if (raw != null) Arrays.fill(raw, (byte) 0);
                    if (expected != null) Arrays.fill(expected, (byte) 0);
                }
                if (matches) onSuccess.run();
                else {
                    if (onFailure != null) onFailure.run();
                    toast("تعذّر تأكيد بصمة مساحة العمل.");
                }
            }, onFailure);
        } catch (Exception e) {
            if (onFailure != null) onFailure.run();
            toast("تعذّر تهيئة التحقق ببصمة الإصبع.");
        }
    }

    private void showHome() {
        if (!workspaceUnlocked || workspace == null) return;
        currentProject = null;
        currentProjectVersionScreenId = null;
        LinearLayout screen = baseScreen();
        LinearLayout header = row();
        header.setGravity(Gravity.CENTER_VERTICAL);
        if (workspace.generalVault == null) {
            Button createGeneral = smallButton("＋＋", PANEL_HI, Color.WHITE);
            createGeneral.setContentDescription("إنشاء الخزنة العامة");
            createGeneral.setOnClickListener(v -> showVaultSetup(GENERAL_VAULT_ID, "الخزنة العامة", true, null));
            header.addView(createGeneral, new LinearLayout.LayoutParams(dp(56), dp(48)));
        } else {
            header.addView(spacer(56));
        }
        LinearLayout brand = row();
        brand.setGravity(Gravity.CENTER);
        android.widget.ImageView logo = new android.widget.ImageView(this);
        logo.setImageResource(R.drawable.sitr_logo);
        logo.setScaleType(android.widget.ImageView.ScaleType.CENTER_INSIDE);
        logo.setContentDescription("شعار سِتر");
        brand.addView(logo, new LinearLayout.LayoutParams(dp(48), dp(48)));
        brand.addView(spacer(6));
        LinearLayout brandText = column();
        brandText.setGravity(Gravity.CENTER_VERTICAL);
        brandText.addView(text("سِتر", 25, TEXT, true));
        brandText.addView(text("مشاريعك وملفاتك في مكان واحد", 12, MUTED, false));
        brand.addView(brandText);
        header.addView(brand, new LinearLayout.LayoutParams(0, -2, 1));
        if (workspace.generalVault != null) {
            Button openGeneral = smallButton("▣", PANEL_HI, BLUE);
            openGeneral.setTextSize(20);
            openGeneral.setContentDescription("فتح الخزنة العامة");
            openGeneral.setOnClickListener(v -> openGeneralVault());
            header.addView(openGeneral, new LinearLayout.LayoutParams(dp(56), dp(48)));
        } else {
            header.addView(spacer(56));
        }
        screen.addView(header, margins(0, 0, 0, 10));

        LinearLayout lockRow = row();
        lockRow.setGravity(Gravity.CENTER_VERTICAL);
        TextView count = text(workspace.projects.size() + " مشروع", 13, MUTED, false);
        lockRow.addView(count, new LinearLayout.LayoutParams(0, -2, 1));
        Button lock = smallButton("قفل", PANEL_HI, TEXT);
        lock.setOnClickListener(v -> {
            lockWorkspace();
            needsUnlockOnResume = false;
            showLockScreen("قُفلت مساحة العمل.");
        });
        lockRow.addView(lock, new LinearLayout.LayoutParams(dp(72), dp(40)));
        screen.addView(lockRow, margins(0, 0, 0, 10));

        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(false);
        LinearLayout grid = column();
        grid.setPadding(0, dp(2), 0, dp(8));
        if (workspace.projects.isEmpty()) {
            LinearLayout empty = column();
            empty.setGravity(Gravity.CENTER);
            empty.setPadding(dp(22), dp(36), dp(22), dp(36));
            empty.setBackground(shape(PANEL, BORDER, 20));
            empty.addView(text("لا توجد مشاريع بعد", 18, TEXT, true));
            empty.addView(text("اضغط زر + أسفل الشاشة لإنشاء أول مشروع.", 14, MUTED, false), margins(0, 8, 0, 0));
            grid.addView(empty, margins(0, 14, 0, 0));
        } else {
            for (int i = 0; i < workspace.projects.size(); i += 2) {
                LinearLayout projectRow = row();
                projectRow.setGravity(Gravity.CENTER_VERTICAL);
                addProjectTile(projectRow, workspace.projects.get(i));
                projectRow.addView(spacer(10));
                if (i + 1 < workspace.projects.size()) addProjectTile(projectRow, workspace.projects.get(i + 1));
                else projectRow.addView(new View(this), new LinearLayout.LayoutParams(0, dp(112), 1));
                grid.addView(projectRow, margins(0, 0, 0, 10));
            }
        }
        scroll.addView(grid, new ScrollView.LayoutParams(-1, -2));
        screen.addView(scroll, new LinearLayout.LayoutParams(-1, 0, 1));

        LinearLayout footer = row();
        footer.setGravity(Gravity.CENTER);
        TextView addProject = plusButton();
        addProject.setContentDescription("إضافة مشروع جديد");
        addProject.setOnClickListener(v -> promptNewProject());
        footer.addView(addProject, new LinearLayout.LayoutParams(dp(62), dp(62)));
        screen.addView(footer, margins(0, 8, 0, 0));
        setContentView(screen);
    }

    private void addProjectTile(LinearLayout parent, Project project) {
        String label = project.name + "\n" + project.versions.size() + " إصدار";
        Button tile = button(label, project.color == 0 ? PROJECT_COLORS[0] : project.color, Color.WHITE);
        tile.setTextSize(15);
        tile.setMaxLines(3);
        tile.setGravity(Gravity.CENTER);
        tile.setBackground(shape(project.color == 0 ? PROJECT_COLORS[0] : project.color, Color.TRANSPARENT, 20));
        tile.setOnClickListener(v -> showProject(project));
        tile.setOnLongClickListener(v -> {
            confirmDeleteProject(project);
            return true;
        });
        parent.addView(tile, new LinearLayout.LayoutParams(0, dp(112), 1));
    }

    private void promptNewProject() {
        EditText name = field("ما اسم المشروع الجديد؟", InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_CAP_SENTENCES);
        AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle("مشروع جديد")
                .setView(name)
                .setNegativeButton("إلغاء", null)
                .setPositiveButton("إضافة", null)
                .create();
        dialog.setOnShowListener(ignored -> dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> {
            String projectName = name.getText().toString().trim();
            if (projectName.isEmpty()) { name.setError("اكتب اسم المشروع"); return; }
            if (projectName.length() > 70) { name.setError("اجعل الاسم أقصر من ٧٠ حرفًا"); return; }
            Project project = new Project();
            project.name = projectName;
            project.color = PROJECT_COLORS[random.nextInt(PROJECT_COLORS.length)];
            workspace.projects.add(project);
            if (saveWorkspace()) {
                dialog.dismiss();
                showHome();
            } else {
                workspace.projects.remove(project);
            }
        }));
        dialog.show();
    }

    private void confirmDeleteProject(Project project) {
        new AlertDialog.Builder(this)
                .setTitle("حذف المشروع؟")
                .setMessage("سيُحذف المشروع وملفاته المشفرة وخزنته الخاصة من هذا الجهاز.")
                .setNegativeButton("إلغاء", null)
                .setPositiveButton("حذف", (dialog, which) -> {
                    int index = workspace.projects.indexOf(project);
                    if (index < 0) return;
                    workspace.projects.remove(index);
                    if (saveWorkspace()) {
                        LocalFileStore.deleteOwner(this, project.id);
                        LocalFileStore.deleteOwner(this, projectVaultOwner(project));
                        if (currentProject != null && currentProject.id.equals(project.id)) currentProject = null;
                        showHome();
                    } else {
                        workspace.projects.add(Math.min(index, workspace.projects.size()), project);
                    }
                }).show();
    }

    private void showProject(Project project) {
        if (!workspaceUnlocked || workspace == null || !workspace.projects.contains(project)) return;
        selectedProjectFileIds.clear();
        currentProject = project;
        currentProjectVersionScreenId = null;
        LinearLayout screen = baseScreen();
        LinearLayout header = row();
        header.setGravity(Gravity.CENTER_VERTICAL);
        Button back = smallButton("رجوع", PANEL_HI, TEXT);
        back.setOnClickListener(v -> { currentProject = null; showHome(); });
        header.addView(back, new LinearLayout.LayoutParams(dp(78), dp(42)));
        TextView title = text(project.name, 22, TEXT, true);
        title.setGravity(Gravity.CENTER);
        header.addView(title, new LinearLayout.LayoutParams(0, -2, 1));
        Button openSecrets = smallButton("أسرار", PANEL_HI, BLUE);
        openSecrets.setOnClickListener(v -> openProjectVault(project));
        header.addView(openSecrets, new LinearLayout.LayoutParams(dp(78), dp(42)));
        screen.addView(header, margins(0, 0, 0, 10));
        addText(screen, project.versions.size() + " إصدار · اضغط على إصدار لعرض ملفاته", 13, MUTED, false, 0, 10);

        ScrollView scroll = new ScrollView(this);
        LinearLayout grid = column();
        grid.setPadding(0, dp(2), 0, dp(8));
        for (int i = 0; i < project.versions.size(); i += 2) {
            LinearLayout versionRow = row();
            versionRow.setGravity(Gravity.CENTER_VERTICAL);
            addProjectVersionTile(versionRow, project, project.versions.get(i), i);
            versionRow.addView(spacer(10));
            if (i + 1 < project.versions.size()) {
                addProjectVersionTile(versionRow, project, project.versions.get(i + 1), i + 1);
            } else {
                versionRow.addView(new View(this), new LinearLayout.LayoutParams(0, dp(112), 1));
            }
            grid.addView(versionRow, margins(0, 0, 0, 10));
        }
        scroll.addView(grid, new ScrollView.LayoutParams(-1, -2));
        screen.addView(scroll, new LinearLayout.LayoutParams(-1, 0, 1));

        LinearLayout footer = row();
        footer.setGravity(Gravity.CENTER);
        TextView addVersion = plusButton();
        addVersion.setContentDescription("إضافة إصدار جديد للمشروع");
        addVersion.setOnClickListener(v -> promptNewProjectVersion(project));
        footer.addView(addVersion, new LinearLayout.LayoutParams(dp(62), dp(62)));
        screen.addView(footer, margins(0, 8, 0, 0));
        setContentView(screen);
    }

    private void addProjectVersionTile(LinearLayout parent, Project project, ProjectVersion version, int position) {
        int color = PROJECT_COLORS[position % PROJECT_COLORS.length];
        Button tile = button(version.name + "\n" + version.files.size() + " ملف", color, Color.WHITE);
        tile.setTextSize(15);
        tile.setMaxLines(3);
        tile.setGravity(Gravity.CENTER);
        tile.setBackground(shape(color, Color.TRANSPARENT, 20));
        tile.setContentDescription("الإصدار " + version.name + "، " + version.files.size() + " ملف");
        tile.setOnClickListener(v -> openProjectVersion(project, version));
        parent.addView(tile, new LinearLayout.LayoutParams(0, dp(112), 1));
    }

    private void openProjectVersion(Project project, ProjectVersion version) {
        if (!workspaceUnlocked || workspace == null || !workspace.projects.contains(project)
                || !project.versions.contains(version)) return;
        selectedProjectFileIds.clear();
        String previousId = project.selectedVersionId;
        project.selectedVersionId = version.id;
        if (!saveWorkspace()) {
            project.selectedVersionId = previousId;
            toast("تعذّر حفظ اختيار الإصدار؛ سيُفتح للعرض فقط.");
        }
        showProjectVersion(project, version);
    }

    private void showProjectVersion(Project project, ProjectVersion version) {
        if (!workspaceUnlocked || workspace == null || !workspace.projects.contains(project)
                || !project.versions.contains(version)) return;
        Set<String> validFileIds = new LinkedHashSet<>();
        for (VaultAttachment file : version.files) validFileIds.add(file.id);
        selectedProjectFileIds.retainAll(validFileIds);
        currentProject = project;
        currentProjectVersionScreenId = version.id;
        LinearLayout screen = baseScreen();
        LinearLayout header = row();
        header.setGravity(Gravity.CENTER_VERTICAL);
        Button back = smallButton("الإصدارات", PANEL_HI, TEXT);
        back.setOnClickListener(v -> showProject(project));
        header.addView(back, new LinearLayout.LayoutParams(dp(90), dp(42)));
        TextView title = text(version.name, 20, TEXT, true);
        title.setGravity(Gravity.CENTER);
        title.setMaxLines(2);
        header.addView(title, new LinearLayout.LayoutParams(0, -2, 1));
        Button openSecrets = smallButton("أسرار", PANEL_HI, BLUE);
        openSecrets.setOnClickListener(v -> openProjectVault(project));
        header.addView(openSecrets, new LinearLayout.LayoutParams(dp(78), dp(42)));
        screen.addView(header, margins(0, 0, 0, 12));

        addText(screen, "ملفات الإصدار · " + version.files.size() + " ملف", 17, TEXT, true, 0, 4);
        boolean selectionMode = !selectedProjectFileIds.isEmpty();
        addText(screen, selectionMode
                        ? "تم تحديد " + selectedProjectFileIds.size() + " ملفًا. اضغط مطولًا لبدء التحديد، ثم المس الملفات لتغيير الاختيار."
                        : "خزنة الأسرار واحدة ومشتركة للمشروع. تُحفظ الملفات كنسخ مشفّرة داخل سِتر، ويظل الأصل كما هو في الهاتف.",
                11, MUTED, false, 0, 8);
        projectFileStatus = text("", 12, MUTED, false);
        screen.addView(projectFileStatus, margins(0, 0, 0, 6));

        ScrollView scroll = new ScrollView(this);
        LinearLayout files = column();
        if (version.files.isEmpty()) {
            LinearLayout empty = column();
            empty.setGravity(Gravity.CENTER);
            empty.setPadding(dp(18), dp(30), dp(18), dp(30));
            empty.setBackground(shape(PANEL, BORDER, 18));
            empty.addView(text("لا توجد ملفات في هذا الإصدار", 16, TEXT, true));
            empty.addView(text("استخدم زر + لإضافة ملفات هذا الإصدار أو ملفات ZIP.", 13, MUTED, false), margins(0, 8, 0, 0));
            files.addView(empty, margins(0, 2, 0, 0));
        } else {
            for (VaultAttachment file : new ArrayList<>(version.files)) addProjectFileRow(files, project, version, file);
        }
        scroll.addView(files, new ScrollView.LayoutParams(-1, -2));
        screen.addView(scroll, new LinearLayout.LayoutParams(-1, 0, 1));

        LinearLayout footer = column();
        if (selectionMode) {
            LinearLayout selectionHeader = row();
            selectionHeader.setGravity(Gravity.CENTER_VERTICAL);
            selectionHeader.addView(text("المحدد: " + selectedProjectFileIds.size(), 13, TEXT, true),
                    new LinearLayout.LayoutParams(0, dp(38), 1));
            Button selectAll = smallButton("الكل", PANEL_HI, BLUE);
            selectAll.setOnClickListener(v -> selectAllProjectFiles(project, version));
            selectionHeader.addView(selectAll, new LinearLayout.LayoutParams(dp(64), dp(38)));
            selectionHeader.addView(spacer(6));
            Button cancel = smallButton("إلغاء", PANEL_HI, TEXT);
            cancel.setOnClickListener(v -> clearProjectFileSelection(project, version));
            selectionHeader.addView(cancel, new LinearLayout.LayoutParams(dp(64), dp(38)));
            footer.addView(selectionHeader);

            LinearLayout actions = row();
            actions.setGravity(Gravity.CENTER);
            Button export = smallButton("تصدير ZIP", PANEL_HI, BLUE);
            export.setOnClickListener(v -> requestSelectedFilesZip(project, version));
            actions.addView(export, new LinearLayout.LayoutParams(0, dp(42), 1));
            actions.addView(spacer(6));
            Button attach = smallButton("إلى الخزنة", PANEL_HI, BLUE);
            attach.setOnClickListener(v -> startBulkAddToProjectVault(project, version));
            actions.addView(attach, new LinearLayout.LayoutParams(0, dp(42), 1));
            actions.addView(spacer(6));
            Button delete = smallButton("حذف", PANEL_HI, MUTED);
            delete.setOnClickListener(v -> confirmDeleteSelectedProjectFiles(project, version));
            actions.addView(delete, new LinearLayout.LayoutParams(0, dp(42), 1));
            footer.addView(actions, margins(0, 6, 0, 0));
        } else {
            footer.setGravity(Gravity.CENTER);
            TextView addFile = plusButton();
            addFile.setContentDescription("إضافة ملفات للإصدار " + version.name);
            addFile.setOnClickListener(v -> startProjectFilePicker(project, version));
            footer.addView(addFile, new LinearLayout.LayoutParams(dp(62), dp(62)));
        }
        screen.addView(footer, margins(0, 8, 0, 0));
        setContentView(screen);
    }

    private void promptNewProjectVersion(Project project) {
        EditText name = field("اسم الإصدار، مثل 1.0 أو تحديث نوفمبر", InputType.TYPE_CLASS_TEXT);
        LinearLayout form = column();
        form.addView(name);
        AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle("إضافة إصدار للمشروع")
                .setMessage("ملفات الإصدار الجديد ستكون منفصلة؛ أسرار المشروع ستبقى في الخزنة المشتركة نفسها.")
                .setView(form)
                .setNegativeButton("إلغاء", null)
                .setPositiveButton("إضافة", null)
                .create();
        dialog.setOnShowListener(ignored -> dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> {
            String label = name.getText().toString().trim();
            if (label.isEmpty()) { name.setError("اكتب اسم الإصدار"); return; }
            if (label.length() > 50) { name.setError("اجعل الاسم ٥٠ حرفًا أو أقل"); return; }
            if (project.hasVersionName(label)) { name.setError("هذا الاسم مستخدم لإصدار آخر"); return; }
            String previousId = project.selectedVersionId;
            ProjectVersion created = project.addVersion(label);
            if (saveWorkspace()) {
                dialog.dismiss();
                showProject(project);
                toast("أُضيف الإصدار «" + label + "». أضف ملفاته بشكل مستقل.");
            } else {
                project.versions.remove(created);
                project.selectedVersionId = previousId;
                name.setError("تعذّر حفظ الإصدار؛ لم تُحذف أو تُنقل أي ملفات.");
            }
        }));
        dialog.show();
    }

    private void addProjectFileRow(LinearLayout parent, Project project, ProjectVersion version, VaultAttachment file) {
        boolean selectionMode = !selectedProjectFileIds.isEmpty();
        boolean selected = selectedProjectFileIds.contains(file.id);
        LinearLayout card = row();
        card.setGravity(Gravity.CENTER_VERTICAL);
        card.setPadding(dp(12), dp(9), dp(12), dp(9));
        card.setBackground(shape(selected ? PANEL_HI : PANEL, selected ? BLUE : BORDER, 16));
        LinearLayout details = column();
        TextView name = text((selected ? "✓  " : "") + file.name, 14, TEXT, true);
        name.setMaxLines(2);
        details.addView(name);
        details.addView(text(formatFileSize(file.sizeBytes), 11, MUTED, false));
        card.addView(details, new LinearLayout.LayoutParams(0, -2, 1));
        if (!selectionMode) {
            Button open = smallButton("فتح", PANEL_HI, BLUE);
            open.setOnClickListener(v -> openProjectFile(project, version, file));
            card.addView(open, new LinearLayout.LayoutParams(dp(54), dp(40)));
            card.addView(spacer(3));
            Button export = smallButton("تصدير", PANEL_HI, BLUE);
            export.setOnClickListener(v -> requestFileExport(project.id, workspaceKey, file));
            card.addView(export, new LinearLayout.LayoutParams(dp(62), dp(40)));
            card.addView(spacer(3));
            Button remove = smallButton("حذف", PANEL_HI, MUTED);
            remove.setOnClickListener(v -> confirmDeleteProjectFile(project, version, file));
            card.addView(remove, new LinearLayout.LayoutParams(dp(56), dp(40)));
        }
        card.setOnClickListener(v -> {
            if (!selectedProjectFileIds.isEmpty()) toggleProjectFileSelection(project, version, file);
        });
        card.setOnLongClickListener(v -> {
            toggleProjectFileSelection(project, version, file);
            return true;
        });
        parent.addView(card, margins(0, 0, 0, 8));
    }

    private void openProjectFile(Project project, ProjectVersion version, VaultAttachment file) {
        if (!isCurrentProjectFile(project, version, file)) return;
        if (FileSupport.isZip(file.name, file.mimeType)) {
            new AlertDialog.Builder(this)
                    .setTitle("استخراج ملف ZIP؟")
                    .setMessage("سيُفك الأرشيف مؤقتًا داخل سِتر، وتُضاف الملفات الآمنة كنسخ مشفرة إلى هذا الإصدار. لن يتغير الأرشيف أو الملف الأصلي.")
                    .setNegativeButton("إلغاء", null)
                    .setPositiveButton("استخراج", (dialog, which) -> extractProjectZip(project, version, file))
                    .show();
        } else if (FileSupport.isApk(file.name, file.mimeType)) {
            requestApkInstall(project, version, file);
        } else if (FileSupport.isEditableText(file.name, file.mimeType)) {
            openTextEditor(project, version, file);
        } else {
            openProjectFileExternally(project, version, file, false);
        }
    }

    private boolean isCurrentProjectFile(Project project, ProjectVersion version, VaultAttachment file) {
        return workspaceUnlocked && workspace != null && workspace.projects.contains(project)
                && project.versions.contains(version) && version.files.contains(file)
                && currentProject == project && currentProjectVersionScreenId != null
                && currentProjectVersionScreenId.equals(version.id);
    }

    private void extractProjectZip(Project project, ProjectVersion version, VaultAttachment archive) {
        if (!isCurrentProjectFile(project, version, archive) || workspaceKey == null || fileOperationBusy) return;
        SecretKey key = workspaceKey;
        fileOperationBusy = true;
        if (projectFileStatus != null) projectFileStatus.setText("جارٍ فحص ZIP وتشفير الملفات المستخرجة…");
        worker.execute(() -> {
            List<VaultAttachment> extracted = null;
            Exception failure = null;
            try { extracted = LocalFileStore.extractZip(this, key, project.id, archive); }
            catch (Exception e) { failure = e; }
            List<VaultAttachment> result = extracted;
            Exception error = failure;
            runOnUiThread(() -> {
                boolean stillCurrent = error == null && workspaceUnlocked && workspace != null
                        && findProject(project.id) == project && project.findVersion(version.id) == version
                        && version.files.contains(archive);
                if (!stillCurrent) {
                    if (result != null) for (VaultAttachment file : result) {
                        try { LocalFileStore.deleteFile(this, project.id, file.id); } catch (Exception ignored) { }
                    }
                    finishFileOperation();
                    toast(error == null ? "تغيرت الشاشة؛ أُلغيت الإضافة ولم يتغير الأرشيف."
                            : "تعذّر استخراج ZIP. لم تُضف الملفات إلى الإصدار.");
                    return;
                }
                version.files.addAll(result);
                if (saveWorkspace()) {
                    showProjectVersion(project, version);
                    toast("استُخرجت " + result.size() + " ملفات كنسخ مشفرة. بقي الأرشيف والأصل كما هما.");
                } else {
                    version.files.removeAll(result);
                    for (VaultAttachment file : result) {
                        try { LocalFileStore.deleteFile(this, project.id, file.id); } catch (Exception ignored) { }
                    }
                }
                finishFileOperation();
            });
        });
    }

    private void requestApkInstall(Project project, ProjectVersion version, VaultAttachment file) {
        if (Build.VERSION.SDK_INT >= 26 && !getPackageManager().canRequestPackageInstalls()) {
            new AlertDialog.Builder(this)
                    .setTitle("السماح بتثبيت APK")
                    .setMessage("سيفتح Android إعدادًا للسماح المؤقت لِسِتر بطلب تثبيت هذا الملف. بعد العودة، افتح سِتر ببصمة الإصبع ثم اضغط «فتح» على APK مرة أخرى. سيطلب Android موافقتك النهائية على التثبيت.")
                    .setNegativeButton("إلغاء", null)
                    .setPositiveButton("فتح إعداد Android", (dialog, which) -> {
                        try {
                            startActivity(new Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                                    Uri.parse("package:" + getPackageName())));
                        } catch (Exception e) { toast("تعذّر فتح إعداد تثبيت التطبيقات."); }
                    }).show();
            return;
        }
        openProjectFileExternally(project, version, file, true);
    }

    private void openProjectFileExternally(Project project, ProjectVersion version, VaultAttachment file, boolean apk) {
        if (!isCurrentProjectFile(project, version, file) || workspaceKey == null || fileOperationBusy) return;
        SecretKey key = workspaceKey;
        fileOperationBusy = true;
        worker.execute(() -> {
            File plain = null;
            Exception failure = null;
            try { plain = LocalFileStore.decryptToCacheFile(this, key, project.id, file); }
            catch (Exception e) { failure = e; }
            File tempFile = plain;
            Exception error = failure;
            runOnUiThread(() -> {
                if (error != null || tempFile == null || !isCurrentProjectFile(project, version, file)) {
                    if (tempFile != null) tempFile.delete();
                    finishFileOperation();
                    toast("تعذّر تجهيز الملف للفتح؛ بقي مشفرًا داخل سِتر.");
                    return;
                }
                try {
                    Uri uri = FileProvider.getUriForFile(this, getPackageName() + ".fileprovider", tempFile);
                    String mime = apk ? "application/vnd.android.package-archive"
                            : FileSupport.mimeTypeForName(file.name, file.mimeType);
                    Intent view = new Intent(Intent.ACTION_VIEW);
                    view.setDataAndType(uri, mime);
                    view.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
                    view.setClipData(ClipData.newUri(getContentResolver(), "ملف من سِتر", uri));
                    pendingExternalOpenUri = uri;
                    startActivity(Intent.createChooser(view, apk ? "تثبيت التطبيق" : "فتح باستخدام"));
                } catch (Exception e) {
                    tempFile.delete();
                    pendingExternalOpenUri = null;
                    toast(apk ? "تعذّر فتح مثبت Android لهذا الملف." : "لا يوجد تطبيق مناسب لفتح هذا النوع من الملفات.");
                }
                finishFileOperation();
            });
        });
    }

    private void openTextEditor(Project project, ProjectVersion version, VaultAttachment file) {
        if (!isCurrentProjectFile(project, version, file) || workspaceKey == null || fileOperationBusy) return;
        if (file.sizeBytes > FileSupport.MAX_EDIT_BYTES) {
            toast("الملفات النصية الأكبر من 1 ميغابايت تُفتح خارجيًا أو تُصدّر للتعديل.");
            return;
        }
        SecretKey key = workspaceKey;
        fileOperationBusy = true;
        worker.execute(() -> {
            byte[] contents = null;
            Exception failure = null;
            try { contents = LocalFileStore.readDecryptedBytes(this, key, project.id, file, FileSupport.MAX_EDIT_BYTES); }
            catch (Exception e) { failure = e; }
            byte[] plain = contents;
            Exception error = failure;
            runOnUiThread(() -> {
                finishFileOperation();
                if (error != null || plain == null || !isCurrentProjectFile(project, version, file)) {
                    if (plain != null) Arrays.fill(plain, (byte) 0);
                    toast("تعذّر فتح النص؛ بقي الملف مشفرًا.");
                    return;
                }
                String initial = new String(plain, StandardCharsets.UTF_8);
                Arrays.fill(plain, (byte) 0);
                showProjectTextEditor(project, version, file, initial);
            });
        });
    }

    private void showProjectTextEditor(Project project, ProjectVersion version, VaultAttachment file, String initialText) {
        if (!isCurrentProjectFile(project, version, file)) return;
        EditText editor = field("النص أو الكود", InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_MULTI_LINE);
        editor.setTextDirection(View.TEXT_DIRECTION_LTR);
        editor.setGravity(Gravity.TOP | Gravity.START);
        editor.setTypeface(Typeface.MONOSPACE);
        editor.setMinLines(14);
        editor.setText(initialText);
        ScrollView scroll = new ScrollView(this);
        scroll.addView(editor, new ScrollView.LayoutParams(-1, -2));
        AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle(file.name)
                .setView(scroll)
                .setNegativeButton("إغلاق", null)
                .setPositiveButton("حفظ مشفرًا", null)
                .create();
        trackSensitiveDialog(dialog, editor);
        dialog.setOnDismissListener(ignored -> clearSensitiveDialog(dialog, editor));
        dialog.setOnShowListener(ignored -> dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> {
            byte[] updated = editor.getText().toString().getBytes(StandardCharsets.UTF_8);
            if (updated.length > FileSupport.MAX_EDIT_BYTES) {
                Arrays.fill(updated, (byte) 0);
                editor.setError("الحد الأقصى للتحرير 1 ميغابايت.");
                return;
            }
            Button save = dialog.getButton(AlertDialog.BUTTON_POSITIVE);
            save.setEnabled(false);
            fileOperationBusy = true;
            worker.execute(() -> {
                VaultAttachment replacement = null;
                Exception failure = null;
                try { replacement = LocalFileStore.importBytes(this, workspaceKey, project.id, updated,
                        file.name, file.mimeType); }
                catch (Exception e) { failure = e; }
                finally { Arrays.fill(updated, (byte) 0); }
                VaultAttachment newFile = replacement;
                Exception error = failure;
                runOnUiThread(() -> {
                    if (error != null || newFile == null || !isCurrentProjectFile(project, version, file)) {
                        if (newFile != null) try { LocalFileStore.deleteFile(this, project.id, newFile.id); } catch (Exception cleanupFailure) { }
                        finishFileOperation();
                        if (dialog.isShowing()) save.setEnabled(true);
                        toast("تعذّر حفظ التعديل؛ بقي الملف السابق مشفرًا كما هو.");
                        return;
                    }
                    int index = version.files.indexOf(file);
                    if (index < 0) {
                        try { LocalFileStore.deleteFile(this, project.id, newFile.id); } catch (Exception cleanupFailure) { }
                        finishFileOperation();
                        return;
                    }
                    version.files.set(index, newFile);
                    if (saveWorkspace()) {
                        try { LocalFileStore.deleteFile(this, project.id, file.id); } catch (Exception cleanupFailure) { }
                        dialog.dismiss();
                        showProjectVersion(project, version);
                        toast("حُفظ النص أو الكود مشفرًا داخل الإصدار.");
                    } else {
                        version.files.set(index, file);
                        try { LocalFileStore.deleteFile(this, project.id, newFile.id); } catch (Exception cleanupFailure) { }
                        if (dialog.isShowing()) save.setEnabled(true);
                    }
                    finishFileOperation();
                });
            });
        }));
        dialog.show();
        if (dialog.getWindow() != null) dialog.getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE);
    }

    private void startProjectFilePicker(Project project, ProjectVersion version) {
        if (!workspaceUnlocked || currentProject == null || !currentProject.id.equals(project.id) || projectFileImportBusy) return;
        pendingProjectId = project.id;
        pendingProjectVersionId = version.id;
        beginExternalPicker();
        try {
            projectFilePicker.launch(new String[] {"*/*"});
        } catch (Exception e) {
            finishExternalPicker();
            pendingProjectId = null;
            pendingProjectVersionId = null;
            toast("تعذّر فتح مستعرض الملفات.");
        }
    }

    private void onProjectFilesSelected(List<Uri> selectedUris) {
        finishExternalPicker();
        String projectId = pendingProjectId;
        String versionId = pendingProjectVersionId;
        pendingProjectId = null;
        pendingProjectVersionId = null;
        if (selectedUris == null || selectedUris.isEmpty() || projectId == null || versionId == null
                || !workspaceUnlocked || workspaceKey == null) return;
        Project project = findProject(projectId);
        if (project == null) return;
        ProjectVersion version = project.findVersion(versionId);
        if (version == null) return;
        List<Uri> uris = new ArrayList<>(selectedUris);
        SecretKeySpec key = workspaceKey;
        projectFileImportBusy = true;
        fileOperationBusy = true;
        if (projectFileStatus != null) projectFileStatus.setText("جارٍ تشفير الملفات داخل الإصدار…");
        worker.execute(() -> {
            List<VaultAttachment> imported = new ArrayList<>();
            int failures = 0;
            for (Uri uri : uris) {
                try {
                    imported.add(LocalFileStore.importFile(this, key, project.id, uri,
                            documentDisplayName(uri), getContentResolver().getType(uri)));
                } catch (Exception e) { failures++; }
            }
            final int failed = failures;
            runOnUiThread(() -> {
                projectFileImportBusy = false;
                if (!workspaceUnlocked || workspace == null || findProject(project.id) != project) {
                    for (VaultAttachment file : imported) {
                        try { LocalFileStore.deleteFile(this, project.id, file.id); } catch (Exception ignored) { }
                    }
                    finishFileOperation();
                    return;
                }
                version.files.addAll(imported);
                if (!saveWorkspace()) {
                    for (VaultAttachment file : imported) {
                        try { LocalFileStore.deleteFile(this, project.id, file.id); } catch (Exception ignored) { }
                    }
                    version.files.removeAll(imported);
                    if (projectFileStatus != null) projectFileStatus.setText("تعذّر حفظ القائمة؛ لم تُضف الملفات.");
                    finishFileOperation();
                    return;
                }
                toast(failed == 0 ? "حُفظت " + imported.size() + " نسخة مشفّرة في «" + version.name
                        + "». الملف الأصلي لم يتغير." : "حُفظ " + imported.size() + " ملفًا في «" + version.name
                        + "»؛ تعذّر استيراد " + failed + ". الأصل لم يتغير.");
                showProjectVersion(project, version);
                finishFileOperation();
            });
        });
    }

    private void startSecretFilePicker() {
        if (currentVaultSession == null || editorAttachments == null || editorFileImportBusy) return;
        pendingSecretAttachmentSession = currentVaultSession;
        pendingSecretAttachmentOwnerId = currentVaultSession.vault.id;
        beginExternalPicker();
        try {
            secretFilePicker.launch(new String[] {"*/*"});
        } catch (Exception e) {
            finishExternalPicker();
            pendingSecretAttachmentSession = null;
            pendingSecretAttachmentOwnerId = null;
            toast("تعذّر فتح مستعرض الملفات.");
        }
    }

    private void onSecretFilesSelected(List<Uri> selectedUris) {
        finishExternalPicker();
        VaultSession session = pendingSecretAttachmentSession;
        String ownerId = pendingSecretAttachmentOwnerId;
        pendingSecretAttachmentSession = null;
        pendingSecretAttachmentOwnerId = null;
        if (selectedUris == null || selectedUris.isEmpty() || session == null || ownerId == null
                || session != currentVaultSession || editorAttachments == null || session.key == null) return;
        int remaining = 20 - editorAttachments.size();
        if (remaining <= 0) { toast("الحد الأقصى ٢٠ ملفًا لكل سر."); return; }
        List<Uri> uris = new ArrayList<>(selectedUris.subList(0, Math.min(remaining, selectedUris.size())));
        boolean truncated = selectedUris.size() > uris.size();
        SecretKey key = session.key;
        editorFileImportBusy = true;
        fileOperationBusy = true;
        if (vaultStatus != null) vaultStatus.setText("جارٍ تشفير الملفات وربطها بهذا السر…");
        worker.execute(() -> {
            List<VaultAttachment> imported = new ArrayList<>();
            int failures = 0;
            for (Uri uri : uris) {
                try {
                    imported.add(LocalFileStore.importFile(this, key, ownerId, uri,
                            documentDisplayName(uri), getContentResolver().getType(uri)));
                } catch (Exception e) { failures++; }
            }
            final int failed = failures;
            runOnUiThread(() -> {
                editorFileImportBusy = false;
                if (session != currentVaultSession || editorAttachments == null || !workspaceUnlocked) {
                    for (VaultAttachment file : imported) {
                        try { LocalFileStore.deleteFile(this, ownerId, file.id); } catch (Exception ignored) { }
                    }
                    finishFileOperation();
                    return;
                }
                editorAttachments.addAll(imported);
                editorNewAttachments.addAll(imported);
                renderEditorAttachments();
                if (failed > 0) toast("أُضيف " + imported.size() + " ملفًا؛ تعذّر استيراد " + failed + ".");
                if (truncated) toast("تسمح كل خزنة بحد أقصى ٢٠ ملفًا لكل سر.");
                if (vaultStatus != null) vaultStatus.setText("احفظ السجل لإدراج هذه الملفات المشفرة معه.");
                finishFileOperation();
            });
        });
    }

    private void renderEditorAttachments() {
        if (editorAttachmentList == null || editorAttachments == null) return;
        editorAttachmentList.removeAllViews();
        if (editorAttachments.isEmpty()) {
            editorAttachmentList.addView(text("لا توجد ملفات مرتبطة بهذا السر.", 12, MUTED, false));
            return;
        }
        for (VaultAttachment file : new ArrayList<>(editorAttachments)) {
            LinearLayout row = row();
            row.setGravity(Gravity.CENTER_VERTICAL);
            row.addView(text(file.name + " · " + formatFileSize(file.sizeBytes), 12, TEXT, false),
                    new LinearLayout.LayoutParams(0, -2, 1));
            Button remove = smallButton("إزالة", PANEL_HI, MUTED);
            remove.setOnClickListener(v -> {
                editorAttachments.remove(file);
                if (editorNewAttachments.remove(file)) {
                    try { LocalFileStore.deleteFile(this, editorVaultOwnerId, file.id); } catch (Exception ignored) { }
                } else if (!editorRemovedAttachments.contains(file)) {
                    editorRemovedAttachments.add(file);
                }
                renderEditorAttachments();
            });
            row.addView(remove, new LinearLayout.LayoutParams(dp(62), dp(36)));
            editorAttachmentList.addView(row, margins(0, 2, 0, 2));
        }
    }

    private void cleanupEditorAttachments() {
        if (editorNewAttachments == null || editorVaultOwnerId == null) return;
        for (VaultAttachment file : editorNewAttachments) {
            try { LocalFileStore.deleteFile(this, editorVaultOwnerId, file.id); } catch (Exception ignored) { }
        }
    }

    private void confirmDeleteProjectFile(Project project, ProjectVersion version, VaultAttachment file) {
        new AlertDialog.Builder(this)
                .setTitle("حذف الملف؟")
                .setMessage("سيُحذف الملف المشفر من إصدار «" + version.name + "». يظل الملف الأصلي في مكانه على الهاتف.")
                .setNegativeButton("إلغاء", null)
                .setPositiveButton("حذف", (dialog, which) -> {
                    int index = version.files.indexOf(file);
                    if (index < 0) return;
                    version.files.remove(index);
                    if (saveWorkspace()) {
                        try { LocalFileStore.deleteFile(this, project.id, file.id); }
                        catch (Exception e) { toast("أُزيل الملف من الإصدار لكن تعذّر تنظيف النسخة المشفرة."); }
                        showProjectVersion(project, version);
                    } else {
                        version.files.add(Math.min(index, version.files.size()), file);
                    }
                }).show();
    }

    private List<VaultAttachment> selectedProjectFiles(Project project, ProjectVersion version) {
        List<VaultAttachment> selected = new ArrayList<>();
        if (!workspaceUnlocked || workspace == null || !workspace.projects.contains(project)
                || !project.versions.contains(version)) return selected;
        for (VaultAttachment file : version.files) {
            if (selectedProjectFileIds.contains(file.id)) selected.add(file);
        }
        return selected;
    }

    private void toggleProjectFileSelection(Project project, ProjectVersion version, VaultAttachment file) {
        if (!workspaceUnlocked || currentProject != project || currentProjectVersionScreenId == null
                || !currentProjectVersionScreenId.equals(version.id) || !version.files.contains(file)) return;
        if (selectedProjectFileIds.contains(file.id)) selectedProjectFileIds.remove(file.id);
        else selectedProjectFileIds.add(file.id);
        showProjectVersion(project, version);
    }

    private void selectAllProjectFiles(Project project, ProjectVersion version) {
        selectedProjectFileIds.clear();
        for (VaultAttachment file : version.files) selectedProjectFileIds.add(file.id);
        showProjectVersion(project, version);
    }

    private void clearProjectFileSelection(Project project, ProjectVersion version) {
        selectedProjectFileIds.clear();
        showProjectVersion(project, version);
    }

    private void confirmDeleteSelectedProjectFiles(Project project, ProjectVersion version) {
        List<VaultAttachment> selected = selectedProjectFiles(project, version);
        if (selected.isEmpty()) return;
        new AlertDialog.Builder(this)
                .setTitle("حذف " + selected.size() + " ملفًا؟")
                .setMessage("سيُحذف من سِتر فقط النسخ المشفرة المحددة في الإصدار «" + version.name
                        + "». الملفات الأصلية في الهاتف ستبقى كما هي.")
                .setNegativeButton("إلغاء", null)
                .setPositiveButton("حذف المحدد", (dialog, which) -> {
                    List<VaultAttachment> oldOrder = new ArrayList<>(version.files);
                    Set<String> ids = new LinkedHashSet<>();
                    for (VaultAttachment file : selected) ids.add(file.id);
                    for (int i = version.files.size() - 1; i >= 0; i--) {
                        if (ids.contains(version.files.get(i).id)) version.files.remove(i);
                    }
                    if (!saveWorkspace()) {
                        version.files.clear();
                        version.files.addAll(oldOrder);
                        return;
                    }
                    int failures = 0;
                    for (VaultAttachment file : selected) {
                        try { LocalFileStore.deleteFile(this, project.id, file.id); }
                        catch (Exception e) { failures++; }
                    }
                    selectedProjectFileIds.clear();
                    showProjectVersion(project, version);
                    toast(failures == 0 ? "حُذفت النسخ المحددة من سِتر؛ لم تتغير الملفات الأصلية."
                            : "أُزيلت المراجع من الإصدار، لكن تعذّر تنظيف " + failures + " نسخة مشفرة.");
                }).show();
    }

    private void requestSelectedFilesZip(Project project, ProjectVersion version) {
        List<VaultAttachment> selected = selectedProjectFiles(project, version);
        if (selected.isEmpty() || workspaceKey == null) return;
        new AlertDialog.Builder(this)
                .setTitle("تصدير المحدد كـZIP")
                .setMessage("سيحتوي ملف ZIP على نسخ غير مشفرة من " + selected.size()
                        + " ملفًا. اختر موقعًا آمنًا؛ لن تتغير النسخ المشفرة أو الملفات الأصلية.")
                .setNegativeButton("إلغاء", null)
                .setPositiveButton("اختيار الموقع", (dialog, which) -> {
                    pendingBulkExportAttachments = new ArrayList<>(selected);
                    pendingBulkExportOwnerId = project.id;
                    pendingBulkExportKey = workspaceKey;
                    pendingBulkExportProjectId = project.id;
                    pendingBulkExportVersionId = version.id;
                    beginExternalPicker();
                    String name = safeDocumentName(project.name + "-" + version.name + ".zip");
                    try { bulkExportPicker.launch(name); }
                    catch (Exception e) {
                        finishExternalPicker();
                        clearPendingBulkExport();
                        toast("تعذّر فتح اختيار مكان التصدير.");
                    }
                }).show();
    }

    private void onBulkExportDestinationSelected(Uri destination) {
        finishExternalPicker();
        List<VaultAttachment> requested = pendingBulkExportAttachments;
        String ownerId = pendingBulkExportOwnerId;
        SecretKey key = pendingBulkExportKey;
        String projectId = pendingBulkExportProjectId;
        String versionId = pendingBulkExportVersionId;
        clearPendingBulkExport();
        if (destination == null || requested == null || ownerId == null || key == null || !workspaceUnlocked) return;
        Project project = findProject(projectId);
        ProjectVersion version = project == null ? null : project.findVersion(versionId);
        if (project == null || version == null || !project.id.equals(ownerId) || key != workspaceKey) return;
        List<VaultAttachment> current = new ArrayList<>();
        for (VaultAttachment requestedFile : requested) {
            for (VaultAttachment file : version.files) {
                if (file.id.equals(requestedFile.id)) { current.add(file); break; }
            }
        }
        if (current.size() != requested.size() || current.isEmpty()) {
            toast("تغيرت قائمة الملفات؛ لم يبدأ التصدير.");
            return;
        }
        fileOperationBusy = true;
        if (projectFileStatus != null) projectFileStatus.setText("جارٍ إنشاء ZIP…");
        worker.execute(() -> {
            Exception failure = null;
            try { LocalFileStore.exportFilesZip(this, key, ownerId, current, destination); }
            catch (Exception e) { failure = e; }
            Exception error = failure;
            runOnUiThread(() -> {
                finishFileOperation();
                selectedProjectFileIds.clear();
                if (error == null) toast("تم إنشاء ZIP غير مشفر في الموقع الذي اخترته.");
                else toast("تعذّر إكمال التصدير؛ إذا ظهر ملف ZIP جزئي في الموقع فاحذفه يدويًا. بقيت النسخ داخل سِتر مشفرة.");
                if (workspaceUnlocked && findProject(projectId) == project
                        && currentProjectVersionScreenId != null && currentProjectVersionScreenId.equals(versionId)) {
                    showProjectVersion(project, version);
                }
            });
        });
    }

    private void clearPendingBulkExport() {
        pendingBulkExportAttachments = null;
        pendingBulkExportOwnerId = null;
        pendingBulkExportKey = null;
        pendingBulkExportProjectId = null;
        pendingBulkExportVersionId = null;
    }

    private String safeDocumentName(String name) {
        if (name == null) return "sitr-export.zip";
        String safe = name.replace('/', '_').replace('\\', '_').replace('\n', '_').replace('\r', '_').trim();
        return safe.isEmpty() ? "sitr-export.zip" : safe;
    }

    private void startBulkAddToProjectVault(Project project, ProjectVersion version) {
        List<VaultAttachment> selected = selectedProjectFiles(project, version);
        if (selected.isEmpty()) return;
        if (selected.size() > 20) {
            toast("يمكن ربط 20 ملفًا كحد أقصى بسجل واحد. قلّل التحديد وحاول مجددًا.");
            return;
        }
        clearPendingBulkAttach();
        pendingBulkAttachFiles = new ArrayList<>(selected);
        pendingBulkAttachProjectId = project.id;
        pendingBulkAttachVersionId = version.id;
        openProjectVault(project);
    }

    private void promptBulkAttachTarget() {
        List<VaultAttachment> pending = pendingBulkAttachFiles;
        String projectId = pendingBulkAttachProjectId;
        if (pending == null || pending.isEmpty() || projectId == null || currentVaultSession == null
                || currentVaultIsGeneral || currentProject == null || !projectId.equals(currentProject.id)) {
            clearPendingBulkAttach();
            return;
        }
        if (currentVaultSession.items.isEmpty()) {
            AlertDialog dialog = new AlertDialog.Builder(this)
                    .setTitle("إنشاء سجل لاستقبال الملفات")
                    .setMessage("لا توجد سجلات في خزنة هذا المشروع بعد. أنشئ سجلًا باسم وسر صحيحين، وسيُربط المحدد به كمرفقات مشفرة.")
                    .setNegativeButton("إلغاء", (d, which) -> clearPendingBulkAttach())
                    .setPositiveButton("إنشاء سجل", (d, which) -> showVaultItemEditor(null))
                    .create();
            dialog.setOnCancelListener(ignored -> clearPendingBulkAttach());
            dialog.show();
            return;
        }
        String[] labels = new String[currentVaultSession.items.size()];
        for (int i = 0; i < currentVaultSession.items.size(); i++) {
            VaultItem item = currentVaultSession.items.get(i);
            labels[i] = item.account == null || item.account.trim().isEmpty()
                    ? item.title : item.title + " · " + item.account;
        }
        AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle("اختر سجل الخزنة")
                .setItems(labels, (d, which) -> {
                    if (which >= 0 && which < currentVaultSession.items.size()) {
                        attachPendingFilesToVaultItem(currentVaultSession.items.get(which), projectId);
                    }
                })
                .setNegativeButton("إلغاء", (d, which) -> clearPendingBulkAttach())
                .create();
        dialog.setOnCancelListener(ignored -> clearPendingBulkAttach());
        dialog.show();
    }

    private void attachPendingFilesToVaultItem(VaultItem item, String projectId) {
        List<VaultAttachment> sources = pendingBulkAttachFiles == null
                ? new ArrayList<>() : new ArrayList<>(pendingBulkAttachFiles);
        String versionId = pendingBulkAttachVersionId;
        clearPendingBulkAttach();
        VaultSession session = currentVaultSession;
        Project project = findProject(projectId);
        ProjectVersion version = project == null ? null : project.findVersion(versionId);
        if (sources.isEmpty() || project == null || version == null || session == null
                || session != currentVaultSession || currentVaultIsGeneral || item == null
                || !session.items.contains(item) || currentProject == null || !projectId.equals(currentProject.id)
                || workspaceKey == null || session.key == null) {
            toast("تعذّر إكمال الإرفاق؛ لم تتغير ملفات المشروع.");
            return;
        }
        Set<String> currentIds = new LinkedHashSet<>();
        for (VaultAttachment file : version.files) currentIds.add(file.id);
        for (VaultAttachment source : sources) {
            if (!currentIds.contains(source.id)) {
                toast("تغيرت قائمة ملفات الإصدار؛ لم يبدأ الإرفاق.");
                return;
            }
        }
        int existingCount = item.attachments == null ? 0 : item.attachments.size();
        if (existingCount + sources.size() > 20) {
            toast("لا يمكن تجاوز 20 مرفقًا في السجل الواحد.");
            return;
        }
        SecretKey sourceKey = workspaceKey;
        SecretKey destinationKey = session.key;
        String destinationOwnerId = session.vault.id;
        List<VaultAttachment> previousAttachments = item.attachments == null
                ? new ArrayList<>() : new ArrayList<>(item.attachments);
        fileOperationBusy = true;
        worker.execute(() -> {
            List<VaultAttachment> copied = new ArrayList<>();
            Exception failure = null;
            try {
                for (VaultAttachment source : sources) {
                    copied.add(LocalFileStore.copyReencrypted(this, sourceKey, project.id, source,
                            destinationKey, destinationOwnerId));
                }
            } catch (Exception e) { failure = e; }
            List<VaultAttachment> finishedCopies = copied;
            Exception error = failure;
            runOnUiThread(() -> {
                boolean valid = error == null && workspaceUnlocked && currentVaultSession == session
                        && currentProject != null && projectId.equals(currentProject.id)
                        && session.items.contains(item) && findProject(projectId) == project;
                if (!valid) {
                    for (VaultAttachment file : finishedCopies) {
                        try { LocalFileStore.deleteFile(this, destinationOwnerId, file.id); } catch (Exception ignored) { }
                    }
                    finishFileOperation();
                    toast(error == null ? "أُلغيت العملية بعد قفل أو تغيير الخزنة؛ لم تتغير ملفات المشروع."
                            : "تعذّر إعادة تشفير ملف؛ لم تُضف مرفقات إلى الخزنة.");
                    return;
                }
                if (item.attachments == null) item.attachments = new ArrayList<>();
                item.attachments.addAll(finishedCopies);
                if (persistCurrentVault()) {
                    selectedProjectFileIds.clear();
                    showVault();
                    toast("أُضيفت النسخ المحددة مشفرة إلى سجل الخزنة. بقيت ملفات المشروع والأصول كما هي.");
                } else {
                    item.attachments.clear();
                    item.attachments.addAll(previousAttachments);
                    for (VaultAttachment file : finishedCopies) {
                        try { LocalFileStore.deleteFile(this, destinationOwnerId, file.id); } catch (Exception ignored) { }
                    }
                }
                finishFileOperation();
            });
        });
    }

    private void clearPendingBulkAttach() {
        pendingBulkAttachFiles = null;
        pendingBulkAttachProjectId = null;
        pendingBulkAttachVersionId = null;
    }

    private void clearPendingBulkAttachForProject(String projectId) {
        if (pendingBulkAttachFiles == null) return;
        if (projectId == null || projectId.equals(pendingBulkAttachProjectId)) clearPendingBulkAttach();
    }

    private void openProjectVault(Project project) {
        if (project.secretVault == null) {
            showVaultSetup(projectVaultOwner(project), "أسرار " + project.name, false, project.id);
        } else {
            promptVaultUnlock(project.secretVault, "أسرار " + project.name, false, project.id);
        }
    }

    private void openGeneralVault() {
        if (workspace.generalVault == null) {
            showVaultSetup(GENERAL_VAULT_ID, "الخزنة العامة", true, null);
        } else {
            promptVaultUnlock(workspace.generalVault, "الخزنة العامة", true, null);
        }
    }

    private void showVaultSetup(String vaultId, String label, boolean general, String projectId) {
        showVaultSetup(vaultId, label, general, projectId, false);
    }

    private void showVaultSetup(String vaultId, String label, boolean general, String projectId, boolean recoveryReset) {
        LinearLayout form = column();
        form.setPadding(dp(6), dp(4), dp(6), dp(4));
        EditText password = field("كلمة مرور قوية — ٨ أحرف على الأقل", InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        EditText confirm = field("أعد كتابة كلمة المرور", InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        form.addView(password, margins(0, 0, 0, 8));
        form.addView(confirm);
        AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle(recoveryReset ? "تعيين كلمة مرور جديدة" : "إنشاء " + label)
                .setMessage(recoveryReset
                        ? "لن نعرض كلمة المرور القديمة. ستُستبدل بيانات هذه الخزنة فقط بعد حفظ كلمة المرور الجديدة."
                        : "هذه الخزنة لها كلمة مرور مستقلة، ويُطلب تأكيد بصمة الإصبع عند تفعيلها.")
                .setView(form)
                .setNegativeButton("إلغاء", null)
                .setPositiveButton(recoveryReset ? "حفظ الجديدة" : "إنشاء", null)
                .create();
        final boolean[] accepted = {false};
        trackSensitiveDialog(dialog, password, confirm);
        dialog.setOnDismissListener(ignored -> {
            clearSensitiveDialog(dialog, password, confirm);
            if (!accepted[0]) clearPendingBulkAttachForProject(projectId);
        });
        dialog.setOnShowListener(ignored -> dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> {
            char[] first = charsFrom(password);
            char[] second = charsFrom(confirm);
            password.setText("");
            confirm.setText("");
            if (first.length < MIN_PASSWORD_CHARS) {
                Arrays.fill(first, '\0'); Arrays.fill(second, '\0');
                password.setError("اجعل كلمة المرور ٨ أحرف على الأقل."); return;
            }
            if (!Arrays.equals(first, second)) {
                Arrays.fill(first, '\0'); Arrays.fill(second, '\0');
                confirm.setError("كلمتا المرور غير متطابقتين."); return;
            }
            Arrays.fill(second, '\0');
            accepted[0] = true;
            dialog.dismiss();
            pendingVaultPassword = first;
            if (recoveryReset) {
                finishVaultCreation(vaultId, label, general, projectId, true);
            } else {
                requestReauthentication(() -> finishVaultCreation(vaultId, label, general, projectId), () -> {
                    clearPendingVaultPassword();
                    clearPendingBulkAttachForProject(projectId);
                });
            }
        }));
        dialog.show();
    }

    private void finishVaultCreation(String vaultId, String label, boolean general, String projectId) {
        finishVaultCreation(vaultId, label, general, projectId, false);
    }

    private void finishVaultCreation(String vaultId, String label, boolean general, String projectId, boolean recoveryReset) {
        EncryptedVault expectedTarget = recoveryReset ? getVault(general, projectId) : null;
        if (recoveryReset && (expectedTarget == null || !expectedTarget.isInitialized()
                || !vaultId.equals(expectedTarget.id))) {
            clearPendingVaultPassword();
            clearPendingBulkAttachForProject(projectId);
            toast("تغيرت الخزنة المستهدفة؛ لم تُمس أي بيانات.");
            return;
        }
        char[] password = pendingVaultPassword;
        pendingVaultPassword = null;
        if (password == null) return;
        fileOperationBusy = true;
        worker.execute(() -> {
            VaultSession session = null;
            Exception failure = null;
            try { session = VaultCrypto.create(vaultId, password); }
            catch (Exception e) { failure = e; }
            finally { Arrays.fill(password, '\0'); }
            VaultSession created = session;
            Exception error = failure;
            runOnUiThread(() -> {
                if (error != null || created == null || !workspaceUnlocked || workspace == null) {
                    if (created != null) created.destroy();
                    clearPendingBulkAttachForProject(projectId);
                    toast("تعذّر إنشاء الخزنة المشفرة.");
                    finishFileOperation();
                    return;
                }
                EncryptedVault previous = getVault(general, projectId);
                if (recoveryReset && previous != expectedTarget) {
                    created.destroy();
                    clearPendingBulkAttachForProject(projectId);
                    toast("تغيرت الخزنة أثناء العملية؛ لم تُمس البيانات.");
                    finishFileOperation();
                    return;
                }
                if (general) workspace.generalVault = created.vault;
                else {
                    Project project = findProject(projectId);
                    if (project == null) {
                        created.destroy();
                        clearPendingBulkAttachForProject(projectId);
                        finishFileOperation();
                        return;
                    }
                    project.secretVault = created.vault;
                }
                if (!saveWorkspace()) {
                    if (general) workspace.generalVault = previous;
                    else {
                        Project project = findProject(projectId);
                        if (project != null) project.secretVault = previous;
                    }
                    created.destroy();
                    clearPendingBulkAttachForProject(projectId);
                    toast("تعذّر حفظ الخزنة الجديدة؛ بقيت الخزنة القديمة كما هي.");
                    finishFileOperation();
                    return;
                }
                boolean attachmentsRemoved = true;
                if (recoveryReset && previous != null) {
                    attachmentsRemoved = LocalFileStore.deleteOwner(this, previous.id);
                    VaultAttemptLimiter.recordSuccess(this, previous.id);
                    clearPendingBulkAttachForProject(projectId);
                }
                currentProject = general ? null : findProject(projectId);
                openVaultSession(created, label, general, projectId);
                finishFileOperation();
                if (!attachmentsRemoved) toast("أُعيد ضبط الخزنة، لكن تعذّر حذف بعض ملفات مرفقاتها المشفرة القديمة.");
            });
        });
    }

    private void promptVaultUnlock(EncryptedVault vault, String label, boolean general, String projectId) {
        if (vault == null || !vault.isInitialized()) {
            toast("الخزنة غير مهيّأة؛ أنشئها من جديد.");
            return;
        }
        LinearLayout form = column();
        form.setPadding(dp(6), dp(4), dp(6), dp(4));
        EditText password = field("كلمة مرور الخزنة", InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        TextView status = text("أدخل كلمة المرور لفك تشفير محتوى الخزنة. بعد 3 محاولات خاطئة يتزايد وقت الانتظار.", 13, MUTED, false);
        form.addView(password, margins(0, 0, 0, 8));
        form.addView(status);
        AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle("فتح " + label)
                .setView(form)
                .setNegativeButton("إلغاء", null)
                .setPositiveButton("فتح", null)
                .setNeutralButton("نسيت كلمة المرور؟", null)
                .create();
        trackSensitiveDialog(dialog, password);
        final boolean[] continuing = {false};
        dialog.setOnDismissListener(ignored -> {
            clearSensitiveDialog(dialog, password);
            if (!continuing[0]) clearPendingBulkAttachForProject(projectId);
        });
        dialog.setOnShowListener(ignored -> {
            Button open = dialog.getButton(AlertDialog.BUTTON_POSITIVE);
            dialog.getButton(AlertDialog.BUTTON_NEUTRAL).setOnClickListener(v -> {
                continuing[0] = true;
                dialog.dismiss();
                promptVaultPasswordReset(vault, label, general, projectId);
            });
            open.setOnClickListener(v -> {
                if (password.length() == 0) { password.setError("أدخل كلمة المرور أولًا."); return; }
                long remaining = VaultAttemptLimiter.remainingMillis(this, vault.id);
                if (remaining > 0L) {
                    status.setText("انتظر " + formatWait(remaining) + " قبل المحاولة التالية. يمكنك استخدام «نسيت كلمة المرور؟» مع بصمة الإصبع.");
                    return;
                }
                char[] chars = charsFrom(password);
                password.setText("");
                open.setEnabled(false);
                status.setText("جارٍ فك تشفير الخزنة…");
                worker.execute(() -> {
                    VaultSession session = null;
                    Exception failure = null;
                    try { session = VaultCrypto.open(vault, chars); }
                    catch (Exception e) { failure = e; }
                    finally { Arrays.fill(chars, '\0'); }
                    VaultSession result = session;
                    Exception error = failure;
                    runOnUiThread(() -> {
                        if (!dialog.isShowing()) { if (result != null) result.destroy(); return; }
                        open.setEnabled(true);
                        if (error != null || result == null) {
                            long delay = VaultAttemptLimiter.recordFailure(MainActivity.this, vault.id);
                            status.setText(delay > 0L
                                    ? "كلمة المرور غير صحيحة. انتظر " + formatWait(delay) + " قبل المحاولة التالية."
                                    : "كلمة المرور غير صحيحة أو تعذّر فك الخزنة.");
                            return;
                        }
                        VaultAttemptLimiter.recordSuccess(MainActivity.this, vault.id);
                        continuing[0] = true;
                        dialog.dismiss();
                        EncryptedVault current = getVault(general, projectId);
                        if (!workspaceUnlocked || current == null || !vault.id.equals(current.id)) {
                            result.destroy();
                            return;
                        }
                        currentProject = general ? null : findProject(projectId);
                        openVaultSession(result, label, general, projectId);
                    });
                });
            });
        });
        dialog.show();
    }

    private void promptVaultPasswordReset(EncryptedVault target, String label, boolean general, String projectId) {
        if (!workspaceUnlocked || target == null || !target.isInitialized()) return;
        clearPendingBulkAttachForProject(projectId);
        new AlertDialog.Builder(this)
                .setTitle("إعادة ضبط كلمة مرور الخزنة؟")
                .setMessage("لا يمكن استعادة الأسرار المشفرة بكلمة المرور القديمة. بعد التحقق ببصمة الإصبع ثم إنشاء كلمة مرور جديدة وتأكيدها، سيُحذف محتوى هذه الخزنة المحددة نهائيًا (السجلات والأسرار والملاحظات والمرفقات). لن تتأثر ملفات المشروع أو الخزنات الأخرى. لا يمكن التراجع عن الحذف.")
                .setNegativeButton("إلغاء", null)
                .setPositiveButton("أفهم، تحقق بالبصمة", (dialog, which) -> {
                    requestReauthentication(() -> {
                        EncryptedVault current = getVault(general, projectId);
                        if (!workspaceUnlocked || current != target || !target.id.equals(current.id)) {
                            clearPendingBulkAttachForProject(projectId);
                            toast("تغيرت الخزنة؛ لم تُمس أي بيانات.");
                            return;
                        }
                        showVaultSetup(target.id, label, general, projectId, true);
                    }, () -> {
                        clearPendingBulkAttachForProject(projectId);
                        toast("لم يُعَد ضبط الخزنة؛ بقي محتواها كما هو.");
                    });
                })
                .show();
    }

    private String formatWait(long millis) {
        long seconds = Math.max(1L, (millis + 999L) / 1000L);
        if (seconds < 60L) return seconds + " ثانية";
        long minutes = (seconds + 59L) / 60L;
        return minutes + " دقيقة";
    }

    private void openVaultSession(VaultSession session, String label, boolean general, String projectId) {
        if (!workspaceUnlocked || session == null) return;
        destroyVaultSession();
        currentVaultSession = session;
        currentVaultOwnerId = session.vault.id;
        currentVaultLabel = label;
        currentVaultIsGeneral = general;
        if (!general) currentProject = findProject(projectId);
        showVault();
        if (!general && pendingBulkAttachFiles != null && projectId != null
                && projectId.equals(pendingBulkAttachProjectId)) {
            mainHandler.post(() -> {
                if (currentVaultSession == session) promptBulkAttachTarget();
            });
        }
    }

    private void showVault() {
        if (currentVaultSession == null || !workspaceUnlocked) return;
        LinearLayout screen = baseScreen();
        LinearLayout header = row();
        header.setGravity(Gravity.CENTER_VERTICAL);
        Button back = smallButton("رجوع", PANEL_HI, TEXT);
        back.setOnClickListener(v -> closeVault());
        header.addView(back, new LinearLayout.LayoutParams(dp(78), dp(42)));
        LinearLayout titleGroup = column();
        titleGroup.setGravity(Gravity.CENTER);
        titleGroup.addView(text(currentVaultLabel == null ? "الخزنة" : currentVaultLabel, 20, TEXT, true));
        titleGroup.addView(text("مشفّرة بكلمة مرور مستقلة", 11, MUTED, false));
        header.addView(titleGroup, new LinearLayout.LayoutParams(0, -2, 1));
        Button lock = smallButton("قفل", PANEL_HI, BLUE);
        lock.setOnClickListener(v -> closeVault());
        header.addView(lock, new LinearLayout.LayoutParams(dp(68), dp(42)));
        screen.addView(header, margins(0, 0, 0, 12));
        vaultStatus = text("الأسرار مخفية؛ أعد إدخال كلمة المرور لنسخ أي سر أو تعديله.", 12, MUTED, false);
        screen.addView(vaultStatus, margins(0, 0, 0, 10));
        ScrollView scroll = new ScrollView(this);
        LinearLayout list = column();
        if (currentVaultSession.items.isEmpty()) {
            LinearLayout empty = column();
            empty.setGravity(Gravity.CENTER);
            empty.setPadding(dp(18), dp(32), dp(18), dp(32));
            empty.setBackground(shape(PANEL, BORDER, 18));
            empty.addView(text("لا توجد أسرار في هذه الخزنة", 16, TEXT, true));
            empty.addView(text("أضف حسابًا أو API Key أو بيانات توقيع من زر +.", 13, MUTED, false), margins(0, 8, 0, 0));
            list.addView(empty, margins(0, 2, 0, 0));
        } else {
            for (VaultItem item : new ArrayList<>(currentVaultSession.items)) addVaultItemCard(list, item);
        }
        scroll.addView(list, new ScrollView.LayoutParams(-1, -2));
        screen.addView(scroll, new LinearLayout.LayoutParams(-1, 0, 1));
        LinearLayout footer = row();
        footer.setGravity(Gravity.CENTER);
        TextView add = plusButton();
        add.setContentDescription("إضافة سر");
        add.setOnClickListener(v -> showVaultItemEditor(null));
        footer.addView(add, new LinearLayout.LayoutParams(dp(62), dp(62)));
        screen.addView(footer, margins(0, 8, 0, 0));
        setContentView(screen);
    }

    private void addVaultItemCard(LinearLayout parent, VaultItem item) {
        LinearLayout card = column();
        card.setPadding(dp(14), dp(12), dp(14), dp(12));
        card.setBackground(shape(PANEL, BORDER, 17));
        card.addView(text(item.title, 17, TEXT, true));
        if (item.account != null && !item.account.trim().isEmpty()) {
            card.addView(text(item.account, 12, MUTED, false), margins(0, 2, 0, 0));
        }
        if (item.note != null && !item.note.trim().isEmpty()) {
            card.addView(text("توجد ملاحظة محفوظة", 11, MUTED, false), margins(0, 2, 0, 0));
        }
        if (item.attachments != null && !item.attachments.isEmpty()) {
            card.addView(text("ملفات مرتبطة: " + item.attachments.size(), 11, MUTED, false), margins(0, 4, 0, 0));
            for (VaultAttachment attachment : new ArrayList<>(item.attachments)) {
                LinearLayout fileRow = row();
                fileRow.setGravity(Gravity.CENTER_VERTICAL);
                TextView fileName = text(attachment.name, 12, TEXT, false);
                fileName.setMaxLines(2);
                fileRow.addView(fileName, new LinearLayout.LayoutParams(0, -2, 1));
                Button exportFile = smallButton("تصدير", PANEL_HI, BLUE);
                VaultSession session = currentVaultSession;
                String ownerId = currentVaultOwnerId;
                exportFile.setOnClickListener(v -> requireVaultPassword(item, "تصدير", () -> {
                    if (currentVaultSession == session && session != null && session.key != null) {
                        requestFileExport(ownerId, session.key, attachment);
                    }
                }));
                fileRow.addView(exportFile, new LinearLayout.LayoutParams(dp(68), dp(36)));
                card.addView(fileRow, margins(0, 4, 0, 0));
            }
        }
        LinearLayout secretRow = row();
        secretRow.setGravity(Gravity.CENTER_VERTICAL);
        TextView secret = text("••••••••••••", 16, TEXT, false);
        secret.setPadding(dp(12), dp(10), dp(12), dp(10));
        secret.setBackground(shape(PANEL_HI, BORDER, 12));
        secretRow.addView(secret, new LinearLayout.LayoutParams(0, -2, 1));
        ImageButton copy = new ImageButton(this);
        copy.setImageResource(R.drawable.ic_copy);
        copy.setColorFilter(BLUE);
        copy.setScaleType(android.widget.ImageView.ScaleType.CENTER_INSIDE);
        copy.setBackground(shape(PANEL_HI, BORDER, 12));
        copy.setContentDescription("نسخ السر بعد التحقق بكلمة المرور");
        copy.setOnClickListener(v -> requireVaultPassword(item, "نسخ", () -> copySecret(item.secret)));
        secretRow.addView(copy, new LinearLayout.LayoutParams(dp(50), dp(44)));
        card.addView(secretRow, margins(0, 8, 0, 0));
        LinearLayout actions = row();
        Button edit = smallButton("تعديل", PANEL_HI, TEXT);
        edit.setOnClickListener(v -> requireVaultPassword(item, "تعديل", () -> showVaultItemEditor(item)));
        Button delete = smallButton("حذف", PANEL_HI, MUTED);
        delete.setOnClickListener(v -> confirmDeleteVaultItem(item));
        actions.addView(edit, new LinearLayout.LayoutParams(0, dp(40), 1));
        actions.addView(spacer(6));
        actions.addView(delete, new LinearLayout.LayoutParams(0, dp(40), 1));
        card.addView(actions, margins(0, 8, 0, 0));
        parent.addView(card, margins(0, 0, 0, 10));
    }

    private void showVaultItemEditor(VaultItem existing) {
        if (currentVaultSession == null) return;
        boolean editing = existing != null;
        String bulkAttachProjectIdAtOpen = pendingBulkAttachProjectId;
        editorAttachments = editing && existing.attachments != null
                ? new ArrayList<>(existing.attachments) : new ArrayList<>();
        editorVaultOwnerId = currentVaultSession.vault.id;
        editorNewAttachments = new ArrayList<>();
        editorRemovedAttachments = new ArrayList<>();
        editorCommitDone = false;
        LinearLayout form = column();
        form.setPadding(dp(4), dp(4), dp(4), dp(4));
        EditText title = field("اسم السر / المشروع", InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_CAP_SENTENCES);
        EditText account = field("الحساب أو البريد (اختياري)", InputType.TYPE_CLASS_TEXT);
        EditText secret = field("كلمة المرور أو الرمز", InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_MULTI_LINE);
        EditText note = field("ملاحظات أو نص مرتبط (اختياري)", InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_MULTI_LINE);
        secret.setMinLines(2);
        note.setMinLines(3);
        secret.setGravity(Gravity.TOP | Gravity.END);
        note.setGravity(Gravity.TOP | Gravity.END);
        form.addView(title, margins(0, 0, 0, 8));
        form.addView(account, margins(0, 0, 0, 8));
        form.addView(secret, margins(0, 0, 0, 8));
        form.addView(note);
        Button addFiles = smallButton("＋ ملفات مرتبطة بهذا السر", PANEL_HI, BLUE);
        addFiles.setOnClickListener(v -> startSecretFilePicker());
        form.addView(addFiles, margins(0, 10, 0, 6));
        editorAttachmentList = column();
        form.addView(editorAttachmentList);
        renderEditorAttachments();
        if (editing) {
            title.setText(existing.title);
            account.setText(existing.account);
            secret.setText(existing.secret);
            note.setText(existing.note);
        }
        ScrollView editorScroll = new ScrollView(this);
        editorScroll.setFillViewport(false);
        editorScroll.addView(form, new ScrollView.LayoutParams(-1, -2));
        AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle(editing ? "تعديل السر" : "إضافة سر")
                .setView(editorScroll)
                .setNegativeButton("إلغاء", null)
                .setPositiveButton("حفظ مشفرًا", null)
                .create();
        trackSensitiveDialog(dialog, title, account, secret, note);
        dialog.setOnShowListener(ignored -> {
            Button save = dialog.getButton(AlertDialog.BUTTON_POSITIVE);
            final boolean[] saving = {false};
            save.setOnClickListener(v -> {
                if (saving[0] || currentVaultSession == null) return;
                String label = title.getText().toString().trim();
                String secretValue = secret.getText().toString();
                if (label.isEmpty()) { title.setError("اكتب اسمًا لهذا السر"); return; }
                if (secretValue.isEmpty()) { secret.setError("أدخل السر الذي تريد حفظه"); return; }
                if (VaultOperations.hasDuplicateContent(currentVaultSession.items, label, secretValue, existing)) {
                    toast("هذا الاسم والسر محفوظان بالفعل."); return;
                }
                saving[0] = true;
                VaultItem item = editing ? existing : new VaultItem();
                String oldTitle = item.title;
                String oldAccount = item.account;
                String oldSecret = item.secret;
                String oldNote = item.note;
                List<VaultAttachment> oldAttachments = item.attachments == null
                        ? new ArrayList<>() : new ArrayList<>(item.attachments);
                item.title = label;
                item.account = account.getText().toString().trim();
                item.secret = secretValue;
                item.note = note.getText().toString();
                item.attachments = new ArrayList<>(editorAttachments);
                if (!editing && !VaultOperations.addOne(currentVaultSession.items, item)) {
                    saving[0] = false; toast("تعذّر إضافة السجل مرتين."); return;
                }
                if (persistCurrentVault()) {
                    editorCommitDone = true;
                    boolean attachPending = !editing && pendingBulkAttachFiles != null
                            && currentProject != null && currentProject.id.equals(pendingBulkAttachProjectId);
                    String attachProjectId = attachPending ? pendingBulkAttachProjectId : null;
                    for (VaultAttachment removed : editorRemovedAttachments) {
                        try { LocalFileStore.deleteFile(this, currentVaultSession.vault.id, removed.id); }
                        catch (Exception ignoredDelete) { }
                    }
                    dialog.dismiss();
                    showVault();
                    toast(editing ? "تم تحديث السر ومرفقاته المشفرة." : "تم حفظ السر ومرفقاته داخل الخزنة المشفرة.");
                    if (attachPending) attachPendingFilesToVaultItem(item, attachProjectId);
                } else {
                    if (editing) {
                        item.title = oldTitle;
                        item.account = oldAccount;
                        item.secret = oldSecret;
                        item.note = oldNote;
                        item.attachments = oldAttachments;
                    } else {
                        VaultOperations.removeOne(currentVaultSession.items, item);
                    }
                    saving[0] = false;
                }
            });
        });
        dialog.setOnDismissListener(ignored -> {
            clearSensitiveDialog(dialog, title, account, secret, note);
            if (!editorCommitDone) {
                cleanupEditorAttachments();
                clearPendingBulkAttachForProject(bulkAttachProjectIdAtOpen);
            }
            editorAttachmentList = null;
            editorAttachments = null;
            editorNewAttachments = null;
            editorRemovedAttachments = null;
            editorVaultOwnerId = null;
        });
        dialog.show();
        if (dialog.getWindow() != null) dialog.getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE);
    }

    private void requireVaultPassword(VaultItem item, String action, Runnable allowed) {
        if (currentVaultSession == null || !currentVaultSession.items.contains(item)) return;
        VaultSession sessionAtStart = currentVaultSession;
        EncryptedVault vaultAtStart = sessionAtStart.vault;
        EditText password = field("كلمة مرور هذه الخزنة", InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle("تأكيد " + action)
                .setMessage("أدخل كلمة مرور الخزنة لتأكيد " + action + " السر «" + item.title + "».")
                .setView(password)
                .setNegativeButton("إلغاء", null)
                .setPositiveButton("تحقق", null)
                .create();
        trackSensitiveDialog(dialog, password);
        dialog.setOnDismissListener(ignored -> clearSensitiveDialog(dialog, password));
        dialog.setOnShowListener(ignored -> dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> {
            if (password.length() == 0) { password.setError("أدخل كلمة المرور أولًا."); return; }
            char[] chars = charsFrom(password);
            password.setText("");
            Button verify = dialog.getButton(AlertDialog.BUTTON_POSITIVE);
                verify.setEnabled(false);
                worker.execute(() -> {
                    Exception failure = null;
                try { VaultCrypto.verifyPassword(vaultAtStart, chars); }
                catch (Exception e) { failure = e; }
                finally { Arrays.fill(chars, '\0'); }
                Exception error = failure;
                runOnUiThread(() -> {
                    if (!dialog.isShowing()) return;
                    verify.setEnabled(true);
                    if (error != null) {
                        password.setError("كلمة المرور غير صحيحة.");
                    } else if (currentVaultSession != sessionAtStart || !currentVaultSession.items.contains(item)) {
                        dialog.dismiss();
                    } else {
                        dialog.dismiss();
                        allowed.run();
                    }
                });
            });
        }));
        dialog.show();
        if (dialog.getWindow() != null) dialog.getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE);
    }

    private void confirmDeleteVaultItem(VaultItem item) {
        new AlertDialog.Builder(this)
                .setTitle("حذف السر؟")
                .setMessage("سيُحذف هذا السجل من الخزنة المشفرة.")
                .setNegativeButton("إلغاء", null)
                .setPositiveButton("حذف", (dialog, which) -> {
                    if (currentVaultSession == null) return;
                    String ownerId = currentVaultOwnerId;
                    List<VaultAttachment> attachedFiles = item.attachments == null
                            ? new ArrayList<>() : new ArrayList<>(item.attachments);
                    int index = VaultOperations.removeOne(currentVaultSession.items, item);
                    if (index < 0) return;
                    if (persistCurrentVault()) {
                        for (VaultAttachment file : attachedFiles) {
                            try { LocalFileStore.deleteFile(this, ownerId, file.id); } catch (Exception ignored) { }
                        }
                        showVault();
                        toast("تم الحذف.");
                    } else {
                        currentVaultSession.items.add(Math.min(index, currentVaultSession.items.size()), item);
                    }
                }).show();
    }

    private boolean persistCurrentVault() {
        if (currentVaultSession == null || workspaceKey == null || workspace == null) return false;
        EncryptedVault old = getVault(currentVaultIsGeneral, currentProject == null ? null : currentProject.id);
        if (old == null) return false;
        try {
            EncryptedVault updated = VaultCrypto.reencrypt(old, currentVaultSession.key, currentVaultSession.items);
            setVault(currentVaultIsGeneral, currentProject == null ? null : currentProject.id, updated);
            if (!saveWorkspace()) {
                setVault(currentVaultIsGeneral, currentProject == null ? null : currentProject.id, old);
                return false;
            }
            currentVaultSession.vault = updated;
            return true;
        } catch (Exception e) {
            toast("تعذّر تشفير التغيير. لم يُحفظ.");
            return false;
        }
    }

    private EncryptedVault getVault(boolean general, String projectId) {
        if (workspace == null) return null;
        if (general) return workspace.generalVault;
        Project project = findProject(projectId);
        return project == null ? null : project.secretVault;
    }

    private void setVault(boolean general, String projectId, EncryptedVault vault) {
        if (workspace == null) return;
        if (general) workspace.generalVault = vault;
        else {
            Project project = findProject(projectId);
            if (project != null) project.secretVault = vault;
        }
    }

    private void closeVault() {
        destroyVaultSession();
        if (currentVaultIsGeneral) {
            currentProject = null;
            showHome();
        } else {
            Project project = findProject(currentProject == null ? null : currentProject.id);
            if (project == null) { currentProject = null; showHome(); }
            else {
                ProjectVersion version = project.findVersion(currentProjectVersionScreenId);
                if (version == null) showProject(project);
                else showProjectVersion(project, version);
            }
        }
    }

    private void destroyVaultSession() {
        if (currentVaultSession != null) currentVaultSession.destroy();
        currentVaultSession = null;
        currentVaultOwnerId = null;
        currentVaultLabel = null;
    }

    private void copySecret(String value) {
        ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        ClipData clip = ClipData.newPlainText("سر من سِتر", value);
        PersistableBundle extras = new PersistableBundle();
        extras.putBoolean("android.content.extra.IS_SENSITIVE", true);
        clip.getDescription().setExtras(extras);
        clipboard.setPrimaryClip(clip);
        toast("نُسخ السر. سيُمحى من الحافظة بعد ٤٥ ثانية إن ظلّ فيها.");
        mainHandler.postDelayed(() -> {
            try {
                if (clipboard.hasPrimaryClip() && clipboard.getPrimaryClip() != null
                        && clipboard.getPrimaryClip().getItemCount() > 0
                        && value.contentEquals(clipboard.getPrimaryClip().getItemAt(0).coerceToText(this))) {
                    if (Build.VERSION.SDK_INT >= 28) clipboard.clearPrimaryClip();
                    else clipboard.setPrimaryClip(ClipData.newPlainText("", ""));
                }
            } catch (Exception ignored) { }
        }, 45_000L);
    }

    private void requestFileExport(String ownerId, SecretKey key, VaultAttachment file) {
        if (key == null || !workspaceUnlocked) return;
        pendingExportOwnerId = ownerId;
        pendingExportKey = key;
        pendingExportAttachment = file;
        beginExternalPicker();
        String name = file.name == null ? "file" : file.name;
        name = name.replace('/', '_').replace('\\', '_').replace('\n', '_').replace('\r', '_');
        try {
            fileExportPicker.launch(name.isEmpty() ? "file" : name);
        } catch (Exception e) {
            finishExternalPicker();
            clearPendingExport();
            toast("تعذّر فتح اختيار مكان التصدير.");
        }
    }

    private void onExportDestinationSelected(Uri destination) {
        finishExternalPicker();
        String ownerId = pendingExportOwnerId;
        SecretKey key = pendingExportKey;
        VaultAttachment file = pendingExportAttachment;
        clearPendingExport();
        if (destination == null || ownerId == null || key == null || file == null || !workspaceUnlocked) return;
        fileOperationBusy = true;
        worker.execute(() -> {
            Exception failure = null;
            try { LocalFileStore.exportFile(this, key, ownerId, file, destination); }
            catch (Exception e) { failure = e; }
            Exception error = failure;
            runOnUiThread(() -> {
                finishFileOperation();
                if (error == null) toast("تم تصدير نسخة غير مشفرة إلى الموقع الذي اخترته.");
                else toast("تعذّر التصدير؛ بقي الملف الأصلي مشفرًا داخل سِتر.");
            });
        });
    }

    private void clearPendingExport() {
        pendingExportOwnerId = null;
        pendingExportKey = null;
        pendingExportAttachment = null;
    }

    private void revokePendingExternalOpen() {
        Uri uri = pendingExternalOpenUri;
        pendingExternalOpenUri = null;
        if (uri != null) {
            try { revokeUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION); }
            catch (Exception ignored) { }
        }
    }

    private void finishFileOperation() {
        fileOperationBusy = false;
        if (!lockAfterFileOperation) return;
        lockAfterFileOperation = false;
        if (workspaceUnlocked) lockWorkspace();
        needsUnlockOnResume = true;
        if (activityResumed) {
            needsUnlockOnResume = false;
            showLockScreen("أُقفلت مساحة العمل بعد انتهاء معالجة الملفات.");
            beginWorkspaceUnlock();
        }
    }

    private void beginExternalPicker() {
        externalPickerPending = true;
        cancelExternalPickerTimeout();
        externalPickerTimeout = () -> {
            if (!externalPickerPending) return;
            externalPickerPending = false;
            pendingProjectId = null;
            clearPendingExport();
            clearPendingBulkExport();
            lockWorkspace();
            needsUnlockOnResume = false;
            showLockScreen("انتهت مهلة اختيار الملف؛ أُقفلت مساحة العمل.");
        };
        mainHandler.postDelayed(externalPickerTimeout, 10 * 60 * 1000L);
    }

    private void finishExternalPicker() {
        externalPickerPending = false;
        cancelExternalPickerTimeout();
    }

    private void cancelExternalPickerTimeout() {
        if (externalPickerTimeout != null) {
            mainHandler.removeCallbacks(externalPickerTimeout);
            externalPickerTimeout = null;
        }
    }

    private void clearPendingVaultPassword() {
        if (pendingVaultPassword != null) Arrays.fill(pendingVaultPassword, '\0');
        pendingVaultPassword = null;
    }

    private void trackSensitiveDialog(AlertDialog dialog, EditText... inputs) {
        activeSensitiveDialog = dialog;
        for (EditText input : inputs) if (!sensitiveInputs.contains(input)) sensitiveInputs.add(input);
    }

    private void clearSensitiveDialog(AlertDialog dialog, EditText... inputs) {
        for (EditText input : inputs) {
            input.setText("");
            sensitiveInputs.remove(input);
        }
        if (activeSensitiveDialog == dialog) activeSensitiveDialog = null;
    }

    private void clearSensitiveUi() {
        AlertDialog dialog = activeSensitiveDialog;
        if (dialog != null && dialog.isShowing()) dialog.dismiss();
        for (EditText input : new ArrayList<>(sensitiveInputs)) input.setText("");
        sensitiveInputs.clear();
        activeSensitiveDialog = null;
    }

    private void lockWorkspace() {
        if (fileOperationBusy) {
            lockAfterFileOperation = true;
            return;
        }
        cancelExternalPickerTimeout();
        externalPickerPending = false;
        clearSensitiveUi();
        pendingProjectId = null;
        pendingProjectVersionId = null;
        clearPendingExport();
        clearPendingBulkExport();
        clearPendingBulkAttach();
        selectedProjectFileIds.clear();
        pendingSecretAttachmentSession = null;
        pendingSecretAttachmentOwnerId = null;
        editorFileImportBusy = false;
        clearPendingVaultPassword();
        destroyVaultSession();
        if (workspace != null) {
            for (Project project : workspace.projects) {
                project.name = "";
                for (ProjectVersion version : project.versions) {
                    version.name = "";
                    version.files.clear();
                }
                project.versions.clear();
                project.selectedVersionId = null;
                project.secretVault = null;
            }
            workspace.projects.clear();
            workspace.generalVault = null;
        }
        workspace = null;
        currentProject = null;
        currentProjectVersionScreenId = null;
        clearWorkspaceKey();
        workspaceUnlocked = false;
    }

    private void clearWorkspaceKey() {
        if (workspaceKey != null) {
            byte[] bytes = workspaceKey.getEncoded();
            if (bytes != null) Arrays.fill(bytes, (byte) 0);
        }
        workspaceKey = null;
    }

    private boolean saveWorkspace() {
        try {
            if (!workspaceUnlocked || workspaceKey == null || workspace == null) throw new IllegalStateException("Workspace is locked");
            WorkspaceStore.save(this, workspaceKey, workspace);
            return true;
        } catch (Exception e) {
            toast("تعذّر حفظ التغيير المشفر. لم يُحفظ.");
            return false;
        }
    }

    private Project findProject(String id) {
        if (workspace == null || id == null) return null;
        for (Project project : workspace.projects) if (project.id.equals(id)) return project;
        return null;
    }

    private String projectVaultOwner(Project project) {
        return project == null ? "project-vault-missing" : "project-vault-" + project.id;
    }

    private String documentDisplayName(Uri uri) {
        try (Cursor cursor = getContentResolver().query(uri, new String[] {OpenableColumns.DISPLAY_NAME}, null, null, null)) {
            if (cursor != null && cursor.moveToFirst()) {
                int column = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                if (column >= 0) {
                    String name = cursor.getString(column);
                    if (name != null && !name.trim().isEmpty()) return name.replace('\n', ' ').replace('\r', ' ').trim();
                }
            }
        } catch (Exception ignored) { }
        return "ملف";
    }

    private String formatFileSize(long bytes) {
        if (bytes < 1024) return bytes + " بايت";
        if (bytes < 1024L * 1024L) return (bytes / 1024L) + " كيلوبايت";
        if (bytes < 1024L * 1024L * 1024L) return String.format(java.util.Locale.ROOT, "%.1f MB", bytes / (1024.0 * 1024.0));
        return String.format(java.util.Locale.ROOT, "%.2f GB", bytes / (1024.0 * 1024.0 * 1024.0));
    }

    private LinearLayout baseScreen() {
        LinearLayout screen = column();
        screen.setPadding(dp(18), dp(14), dp(18), dp(14));
        screen.setBackgroundColor(BG);
        return screen;
    }

    private void addBrand(LinearLayout parent) {
        LinearLayout brand = row();
        brand.setGravity(Gravity.CENTER_VERTICAL);
        android.widget.ImageView logo = new android.widget.ImageView(this);
        logo.setImageResource(R.drawable.sitr_logo);
        logo.setScaleType(android.widget.ImageView.ScaleType.CENTER_INSIDE);
        logo.setContentDescription("شعار سِتر");
        brand.addView(logo, new LinearLayout.LayoutParams(dp(88), dp(88)));
        LinearLayout title = column();
        title.setPadding(dp(10), 0, 0, 0);
        title.addView(text("سِتر", 21, TEXT, true));
        title.addView(text("مساحة آمنة لمشاريعك", 12, MUTED, false));
        brand.addView(title);
        parent.addView(brand, margins(0, 2, 0, 28));
    }

    private void addText(LinearLayout parent, String value, float size, int color, boolean bold, int top, int bottom) {
        parent.addView(text(value, size, color, bold), margins(0, top, 0, bottom));
    }

    private EditText field(String hint, int inputType) {
        EditText input = new EditText(this);
        input.setTextColor(TEXT);
        input.setHintTextColor(MUTED);
        input.setTextSize(15);
        input.setHint(hint);
        input.setInputType(inputType);
        input.setSingleLine((inputType & InputType.TYPE_TEXT_FLAG_MULTI_LINE) == 0);
        input.setPadding(dp(13), dp(10), dp(13), dp(10));
        input.setBackground(shape(PANEL, BORDER, 13));
        input.setTextDirection(View.TEXT_DIRECTION_FIRST_STRONG);
        input.setGravity((inputType & InputType.TYPE_TEXT_FLAG_MULTI_LINE) != 0
                ? Gravity.TOP | Gravity.END : Gravity.CENTER_VERTICAL | Gravity.END);
        input.setLayoutDirection(View.LAYOUT_DIRECTION_RTL);
        input.setSaveEnabled(false);
        input.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS);
        input.setMinHeight(dp((inputType & InputType.TYPE_TEXT_FLAG_MULTI_LINE) != 0 ? 70 : 52));
        return input;
    }

    private char[] charsFrom(EditText editText) {
        char[] chars = new char[editText.length()];
        editText.getText().getChars(0, editText.length(), chars, 0);
        return chars;
    }

    private Button button(String label, int background, int foreground) {
        Button b = new Button(this);
        b.setText(label);
        b.setTextSize(15);
        b.setAllCaps(false);
        b.setTextColor(foreground);
        b.setTypeface(Typeface.create("sans-serif", Typeface.BOLD));
        b.setBackground(shape(background, Color.TRANSPARENT, 15));
        b.setStateListAnimator(null);
        b.setMinHeight(dp(52));
        b.setPadding(dp(12), 0, dp(12), 0);
        return b;
    }

    private Button smallButton(String label, int background, int foreground) {
        Button b = button(label, background, foreground);
        b.setTextSize(12);
        b.setMinHeight(dp(40));
        b.setPadding(dp(3), 0, dp(3), 0);
        return b;
    }

    private TextView plusButton() {
        TextView add = text("+", 34, Color.WHITE, false);
        add.setGravity(Gravity.CENTER);
        add.setBackground(circle(BLUE));
        add.setElevation(dp(5));
        return add;
    }

    private TextView text(String value, float size, int color, boolean bold) {
        TextView t = new TextView(this);
        t.setText(value);
        t.setTextSize(size);
        t.setTextColor(color);
        t.setTypeface(Typeface.create("sans-serif", bold ? Typeface.BOLD : Typeface.NORMAL));
        t.setGravity(Gravity.CENTER_VERTICAL);
        t.setTextDirection(View.TEXT_DIRECTION_FIRST_STRONG);
        t.setIncludeFontPadding(true);
        return t;
    }

    private LinearLayout column() {
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setLayoutDirection(View.LAYOUT_DIRECTION_RTL);
        return layout;
    }

    private LinearLayout row() {
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.HORIZONTAL);
        layout.setLayoutDirection(View.LAYOUT_DIRECTION_RTL);
        return layout;
    }

    private View spacer(int widthDp) {
        View view = new View(this);
        view.setLayoutParams(new LinearLayout.LayoutParams(dp(widthDp), 1));
        return view;
    }

    private GradientDrawable shape(int fill, int stroke, float radius) {
        GradientDrawable drawable = new GradientDrawable();
        drawable.setColor(fill);
        drawable.setCornerRadius(dp(radius));
        if (stroke != Color.TRANSPARENT) drawable.setStroke(dp(1), stroke);
        return drawable;
    }

    private GradientDrawable circle(int fill) {
        GradientDrawable drawable = new GradientDrawable();
        drawable.setColor(fill);
        drawable.setShape(GradientDrawable.OVAL);
        return drawable;
    }

    private LinearLayout.LayoutParams margins(int width, int top, int right, int bottom) {
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(width == 0 ? -1 : width, -2);
        lp.topMargin = dp(top);
        lp.rightMargin = dp(right);
        lp.bottomMargin = dp(bottom);
        return lp;
    }

    private int dp(float value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }

    private void toast(String message) {
        Toast.makeText(this, message, Toast.LENGTH_SHORT).show();
    }
}
