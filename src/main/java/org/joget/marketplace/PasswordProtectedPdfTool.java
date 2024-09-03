package org.joget.marketplace;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
import org.apache.pdfbox.pdmodel.encryption.AccessPermission;
import org.joget.apps.app.model.AppDefinition;
import org.joget.apps.app.service.AppPluginUtil;
import org.joget.apps.app.service.AppService;
import org.joget.apps.app.service.AppUtil;
import org.joget.apps.form.model.*;
import org.joget.apps.form.service.FileUtil;
import org.joget.apps.form.service.FormUtil;
import org.joget.commons.util.LogUtil;
import org.joget.commons.util.SecurityUtil;
import org.joget.plugin.base.DefaultApplicationPlugin;
import org.joget.workflow.model.WorkflowAssignment;
import org.springframework.context.ApplicationContext;
import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.encryption.StandardProtectionPolicy;


public class PasswordProtectedPdfTool extends DefaultApplicationPlugin {
    private final static String MESSAGE_PATH = "messages/PasswordProtectedPdfTool";

    @Override
    public String getName() {
        return AppPluginUtil.getMessage("org.joget.marketplace.PasswordProtectedPdfTool.pluginLabel", getClassName(), MESSAGE_PATH);
    }

    @Override
    public String getVersion() {
        return "8.0.0";
    }

    @Override
    public String getDescription() {
        return AppPluginUtil.getMessage("org.joget.marketplace.PasswordProtectedPdfTool.pluginDesc", getClassName(), MESSAGE_PATH);
    }

    @Override
    public String getClassName() {
        return getClass().getName();
    }

    @Override
    public String getPropertyOptions() {
        return AppUtil.readPluginResource(getClassName(), "/properties/PasswordProtectedPdfTool.json", null, true, MESSAGE_PATH);
    }

    @Override
    public String getLabel() {
        return AppPluginUtil.getMessage("org.joget.marketplace.PasswordProtectedPdfTool.pluginLabel", getClassName(), MESSAGE_PATH);
    }

    @Override
    public Object execute(Map map) {
        ApplicationContext ac = AppUtil.getApplicationContext();
        AppService appService = (AppService) ac.getBean("appService");
        AppDefinition appDef = AppUtil.getCurrentAppDefinition();

        String formDefIdSourceFile = (String) map.get("formDefIdSourceFile");
        String sourceFileFieldId = (String) map.get("sourceFileFieldId");
        String formDefIdOutputFile = (String) map.get("formDefIdOutputFile");
        String outputFileFieldId = (String) map.get("outputFileFieldId");
        String filePassword = (String) map.get("password");
        filePassword = AppUtil.processHashVariable(filePassword, null, null, null);
        String recordId;

        WorkflowAssignment wfAssignment = (WorkflowAssignment) map.get("workflowAssignment");
        if (wfAssignment != null) {
            recordId = appService.getOriginProcessId(wfAssignment.getProcessId());
        } else {
            recordId = (String) properties.get("recordId");
        }

        Form loadForm;
        File srcFile;

        if (formDefIdSourceFile != null && formDefIdOutputFile != null) {
            try {
                FormData formData = new FormData();
                formData.setPrimaryKeyValue(recordId);
                loadForm = appService.viewDataForm(appDef.getId(), appDef.getVersion().toString(), formDefIdSourceFile, null, null, null, formData, null, null);

                Element el = FormUtil.findElement(sourceFileFieldId, loadForm, formData);
                String pdfFilePath = FormUtil.getElementPropertyValue(el, formData);
                srcFile = FileUtil.getFile(pdfFilePath, loadForm, recordId);

                String password = SecurityUtil.decrypt(filePassword);

                String filePaths = srcFile.getPath();
                List<String> fileList = getFilesList(filePaths);
                StringBuilder resultBuilder = new StringBuilder();
                FormRowSet frs = new FormRowSet();

                for (String filePath : fileList) {
                    File currentFile = new File(filePath.trim());
                    byte[] protectedPdfContent = addPasswordToPDF(currentFile, password);
                    String protectedPdfFileName = writeProtectedPdfFile(currentFile, appService, appDef, formDefIdOutputFile, recordId, protectedPdfContent);
                    if (resultBuilder.length() > 0) {
                        resultBuilder.append(";");
                    }
                    resultBuilder.append(protectedPdfFileName);
                }

                if (!fileList.isEmpty()) {
                    FormRow row = new FormRow();
                    row.put(outputFileFieldId, resultBuilder.toString());
                    frs.add(row);
                    appService.storeFormData(appDef.getAppId(), appDef.getVersion().toString(), formDefIdOutputFile, frs, recordId);
                }

            } catch (IOException ex) {
                LogUtil.error(getClassName(), ex, ex.getMessage());
            }
        }
        return null;
    }

    private byte[] addPasswordToPDF(File pdfFile, String password) throws IOException {
        try (PDDocument document = PDDocument.load(pdfFile)) {
            StandardProtectionPolicy protectionPolicy = new StandardProtectionPolicy(password, password, new AccessPermission());
            protectionPolicy.setEncryptionKeyLength(128);
            document.protect(protectionPolicy);
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            document.save(outputStream);
            return outputStream.toByteArray();
        }
    }

    private String writeProtectedPdfFile(File uploadedFile, AppService appService, AppDefinition appDef, String formDefIdOutputFile, String recordId, byte[] protectedPdfContent) throws IOException {
        String fileNameWithoutExt = FilenameUtils.removeExtension(uploadedFile.getName());
        String fileName = fileNameWithoutExt + "_protected.pdf";
        String tableName = appService.getFormTableName(appDef, formDefIdOutputFile);
        String path = FileUtil.getUploadPath(tableName, recordId);
        File protectedFile = new File(path, fileName);
        FileUtils.writeByteArrayToFile(protectedFile, protectedPdfContent);
        return fileName;
    }

    public List<String> getFilesList(String filePaths) {
        String[] fileArray = filePaths.split(";");
        List<String> fileList = new ArrayList<>();

        String directoryPath = "";
        for (String filePath : fileArray) {
            String fullPath = "";
            String trimmedPath = filePath.trim();
            int lastSeparatorIndex = trimmedPath.lastIndexOf(File.separator);
            if (lastSeparatorIndex != -1) {
                directoryPath = trimmedPath.substring(0, lastSeparatorIndex);
                String fileName = trimmedPath.substring(lastSeparatorIndex + 1);
                fullPath = directoryPath + File.separator + fileName;
            } else {
                fullPath = directoryPath + File.separator + trimmedPath;
            }
            fileList.add(fullPath);
        }
        return fileList;
    }
}
